//! Sealed values survive suspension and replay without a journal mismatch.
//!
//! A Virtual Object keyed by its tenant seals a value, keeps it in state,
//! passes it to another object as a call argument, and suspends. Resuming
//! replays the whole journal: sealing inside `ctx.run` replays the journaled
//! envelope, so `ctx.set` and the call carry the same bytes again. Sealing
//! outside `run` draws a fresh nonce on replay, and Restate reports a journal
//! mismatch.
//!
//! The scenarios share one deployment and run in sequence: on a reused server,
//! concurrent tests would register the same services over each other.

use std::{
    sync::{
        LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use cryptbox::{
    EncryptionKey, EncryptionKeyring, Keys, Record, Sealed, Tenant, TenantId,
    restate::{self, ObjectKey},
};
use restate_e2e_harness::{Call, Restate, ReusePolicy, ServerSpec, launcher_or_skip};
use restate_sdk::prelude::*;
use serde_json::json;

const SERVER: ServerSpec = ServerSpec {
    name: "cryptbox",
    features: &[],
    env: &[],
};

const EMAIL: &str = "ada@example.com";

/// How Restate reports a journal mismatch in an invocation's last failure.
const JOURNAL_MISMATCH: &str = "[570 Journal mismatch]";

#[derive(cryptbox::Seal)]
#[cryptbox(
    id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
    value = String,
    scope = Tenant
)]
struct CustomerEmail;

#[derive(cryptbox::Seal)]
#[cryptbox(
    id = "0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38",
    value = String,
    scope = cryptbox::Recorded<Tenant, i64>
)]
struct CustomerNote;

#[derive(Debug, PartialEq, cryptbox::Record)]
#[cryptbox(
    record = id,
    sealed = SealedCustomer,
    attr(derive(serde::Serialize, serde::Deserialize))
)]
struct Customer {
    #[cryptbox(plaintext)]
    id: i64,
    #[cryptbox(seal = CustomerNote)]
    note: String,
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    Keys::new(EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap())
});

/// How many times each handler started: more than once means its invocation
/// resumed by replaying its journal.
static STORE_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
static RECORD_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
static UNSAFE_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

fn tenant(key: &str) -> Result<Tenant, HandlerError> {
    ObjectKey::<Tenant>::parse(key).map_err(restate::handler_error)
}

/// Keeps one tenant's customer data. Its short inactivity timeout suspends an
/// invocation as soon as it waits.
struct Vault;

#[restate_sdk::object(inactivity_timeout = "100ms")]
impl Vault {
    /// Seals inside `ctx.run`, then keeps, passes, and reopens the value.
    #[handler]
    async fn store(&self, ctx: ObjectContext<'_>, email: String) -> HandlerResult<u64> {
        STORE_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
        let tenant = tenant(ctx.key())?;

        let sealed = restate::seal::<CustomerEmail>(&ctx, &email, &tenant, &*KEYS)
            .name("seal-email")
            .await?;
        ctx.set("email", sealed.clone());
        // Fetched and sealed in one `run`: its plaintext is never a `run` result.
        let copy = email.clone();
        let fetched = restate::seal_with::<CustomerEmail, _>(
            &ctx,
            move || async move { Ok(copy) },
            &tenant,
            &*KEYS,
        )
        .name("fetch-email")
        .await?;
        ctx.set("fetched-email", fetched);
        let length = ctx
            .object_client::<CheckerClient>(ctx.key())
            .length(sealed)
            .call()
            .await?;
        // Longer than the inactivity timeout: the invocation suspends, and
        // resumes by replaying everything above.
        ctx.sleep(Duration::from_millis(500)).await?;

        let stored: Sealed<CustomerEmail> = ctx
            .get("email")
            .await?
            .ok_or_else(|| TerminalError::new("the email was not kept"))?;
        if stored
            .open(&tenant, &*KEYS)
            .map_err(restate::handler_error)?
            != email
        {
            return Err(TerminalError::new("reopened another email").into());
        }
        let fetched: Sealed<CustomerEmail> = ctx
            .get("fetched-email")
            .await?
            .ok_or_else(|| TerminalError::new("the fetched email was not kept"))?;
        if fetched
            .open(&tenant, &*KEYS)
            .map_err(restate::handler_error)?
            != email
        {
            return Err(TerminalError::new("reopened another fetched email").into());
        }

        Ok(length)
    }

    /// Fetches and seals a whole record in one `ctx.run`, then keeps and
    /// reopens it.
    #[handler]
    async fn store_record(&self, ctx: ObjectContext<'_>, note: String) -> HandlerResult<String> {
        RECORD_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
        let tenant = tenant(ctx.key())?;

        let fetch = move || async move { Ok(Customer { id: 7, note }) };
        let sealed = restate::seal_record_with::<Customer, _>(&ctx, fetch, &tenant, &*KEYS)
            .name("seal-customer")
            .await?;
        ctx.set("customer", sealed);
        ctx.sleep(Duration::from_millis(500)).await?;

        let Json(stored) = ctx
            .get::<Json<SealedCustomer>>("customer")
            .await?
            .ok_or_else(|| TerminalError::new("the customer was not kept"))?;
        let customer = Customer::open(stored, &tenant, &*KEYS).map_err(restate::handler_error)?;

        Ok(customer.note)
    }

    /// Seals outside `ctx.run`: the negative control.
    #[handler]
    async fn store_unsafely(&self, ctx: ObjectContext<'_>, email: String) -> HandlerResult<()> {
        UNSAFE_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
        let tenant = tenant(ctx.key())?;

        let sealed = Sealed::<CustomerEmail>::seal(&email, &tenant, &*KEYS)
            .map_err(restate::handler_error)?;
        ctx.set("unsafe-email", sealed);
        ctx.sleep(Duration::from_millis(500)).await?;

        Ok(())
    }
}

/// Opens a sealed email it receives as a call argument.
struct Checker;

#[restate_sdk::object]
impl Checker {
    #[handler]
    async fn length(
        &self,
        ctx: ObjectContext<'_>,
        email: Sealed<CustomerEmail>,
    ) -> HandlerResult<u64> {
        let email = email
            .open(&tenant(ctx.key())?, &*KEYS)
            .map_err(restate::handler_error)?;

        Ok(u64::try_from(email.len())?)
    }
}

fn acme() -> String {
    ObjectKey::<Tenant>::encode(&Tenant(TenantId::new("acme").unwrap())).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs RESTATE_SERVER_BIN, or RESTATE_ADMIN_URL and RESTATE_INGRESS_URL"]
async fn sealed_values_survive_replay() {
    let Some(launcher) = launcher_or_skip(ReusePolicy::Allowed) else {
        return;
    };
    let restate = launcher.launch(&SERVER).await;
    restate
        .deploy(Endpoint::builder().bind(Vault).bind(Checker).build())
        .await;

    a_sealed_value_replays_after_suspension(&restate).await;
    a_sealed_record_replays_after_suspension(&restate).await;
    sealing_outside_run_breaks_replay(&restate).await;

    restate.finish().await;
}

async fn a_sealed_value_replays_after_suspension(restate: &Restate) {
    let reply = tokio::time::timeout(
        Duration::from_secs(60),
        restate.invoke(
            &Call::object("Vault", &acme(), "store"),
            Some(&json!(EMAIL)),
            None,
        ),
    )
    .await
    .expect("the invocation completes: a journal mismatch retries forever");

    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.body, json!(EMAIL.len()));
    assert!(
        STORE_ATTEMPTS.load(Ordering::SeqCst) > 1,
        "the invocation suspended and resumed by replaying its journal"
    );
}

async fn a_sealed_record_replays_after_suspension(restate: &Restate) {
    let reply = tokio::time::timeout(
        Duration::from_secs(60),
        restate.invoke(
            &Call::object("Vault", &acme(), "store_record"),
            Some(&json!("VIP")),
            None,
        ),
    )
    .await
    .expect("the invocation completes: a journal mismatch retries forever");

    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.body, json!("VIP"));
    assert!(RECORD_ATTEMPTS.load(Ordering::SeqCst) > 1, "replayed");
}

async fn sealing_outside_run_breaks_replay(restate: &Restate) {
    let reply = restate
        .invoke(
            &Call::object("Vault", &acme(), "store_unsafely").send(),
            Some(&json!(EMAIL)),
            None,
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let id = reply.invocation_id().to_owned();

    let query = format!(
        "SELECT last_failure, last_failure_related_command_type FROM sys_invocation WHERE id = '{id}'"
    );
    let mismatch = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let rows = restate.admin().sql_or_panic(&query).await;
            let column = |name| rows.first().and_then(|row| row.get(name)?.as_str());
            let mismatch =
                column("last_failure").is_some_and(|failure| failure.starts_with(JOURNAL_MISMATCH));
            if mismatch && column("last_failure_related_command_type") == Some("SetState") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;

    restate.admin().kill(&id).await;
    assert!(
        mismatch.is_ok(),
        "resealing on replay is a journal mismatch on `ctx.set`"
    );
    assert!(UNSAFE_ATTEMPTS.load(Ordering::SeqCst) > 1, "replayed");
}
