use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new() -> Self {
        let id = cryptbox::EncryptionKey::generate()
            .unwrap()
            .id()
            .to_string();
        let path = std::env::temp_dir().join(format!("cryptbox-e2e-{id}"));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Nested Cargo uses its own target directory to avoid the outer test invocation's
// build lock. Lock across processes until the executable is copied: another test
// invocation may build the same binary with different features immediately afterwards.

pub fn build(directory: &Path, binary: &str, features: &str, database: Option<&str>) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| root.join("target"), |target| root.join(target))
        .join("e2e");
    fs::create_dir_all(&target).unwrap();
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(target.join("fixture.lock"))
        .unwrap();
    fs2::FileExt::lock_exclusive(&lock).unwrap();
    let mut command = Command::new(env!("CARGO"));
    command
        .current_dir(root)
        .env("CARGO_TARGET_DIR", &target)
        .args([
            "build",
            "--locked",
            "-p",
            "cryptbox-e2e",
            "--bin",
            binary,
            "--no-default-features",
        ]);
    if !features.is_empty() {
        command.args(["--features", features]);
    }
    if let Some(database) = database {
        command.env("DATABASE_URL", database);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "fixture build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let name = format!("{binary}{}", std::env::consts::EXE_SUFFIX);
    let destination = directory.join(&name);
    fs::copy(target.join("debug").join(name), &destination).unwrap();
    destination
}

#[cfg(any(feature = "sqlx-sqlite", feature = "sqlx-postgres"))]
pub use database::*;

#[cfg(any(feature = "sqlx-sqlite", feature = "sqlx-postgres"))]
mod database {
    use super::*;
    use std::{collections::BTreeMap, ffi::OsString, process::Output};

    pub struct App {
        pub scratch: Scratch,
        pub keys: PathBuf,
        pub database: String,
        backend: &'static str,
        binary: PathBuf,
        env: BTreeMap<String, OsString>,
        #[cfg(feature = "sqlx-postgres")]
        postgres: Option<(String, String)>,
    }

    impl App {
        pub fn new(backend: &'static str, features: &str) -> Self {
            let scratch = Scratch::new();
            let keys = scratch.0.join("keys");
            let database = format!("sqlite://{}?mode=rwc", scratch.0.join("users.db").display());
            let mut app = Self {
                binary: PathBuf::new(),
                scratch,
                keys,
                database,
                backend,
                env: BTreeMap::new(),
                #[cfg(feature = "sqlx-postgres")]
                postgres: None,
            };
            #[cfg(feature = "sqlx-postgres")]
            if backend == "postgres" {
                app.create_postgres();
            }
            app.env
                .insert("DATABASE_URL".into(), app.database.clone().into());
            app.env
                .insert("CRYPTBOX_KEY_DIR".into(), app.keys.as_os_str().to_owned());
            app.env.insert("CRYPTBOX_GENERATION".into(), "1".into());
            app.rebuild(features);
            assert!(app.fail(&["init"], &[]).contains("key configuration"));
            fs::create_dir(&app.keys).unwrap();
            for role in ["encryption", "index"] {
                for generation in 1..=3 {
                    let mut bytes = [0; 32];
                    getrandom::fill(&mut bytes).unwrap();
                    fs::write(
                        app.keys.join(format!("{role}-{generation}.hex")),
                        hex::encode(bytes),
                    )
                    .unwrap();
                }
            }
            if features == "legacy-migration" {
                let mut bytes = [0; 32];
                getrandom::fill(&mut bytes).unwrap();
                fs::write(app.keys.join("legacy.hex"), hex::encode(bytes)).unwrap();
            }
            app.expect(&["init"], &[], "Schema ready.");
            app
        }

        pub fn rebuild(&mut self, features: &str) {
            let features = if features.is_empty() {
                self.backend.to_owned()
            } else {
                format!("{},{features}", self.backend)
            };
            self.binary = build(
                &self.scratch.0,
                "searchable",
                &features,
                Some(&self.database),
            );
        }

        pub fn command(&self, args: &[&str]) -> Command {
            let mut command = Command::new(&self.binary);
            command
                .current_dir(&self.scratch.0)
                .args(args)
                .env_remove("CRYPTBOX_ENCRYPTION")
                .env_remove("CRYPTBOX_INDEX")
                .envs(&self.env);
            command
        }

        pub fn run(&self, args: &[&str], config: &[(&str, &str)], success: bool) -> Output {
            let output = self
                .command(args)
                .envs(config.iter().copied())
                .output()
                .unwrap();
            assert!(
                output.status.code().is_some(),
                "{args:?} terminated by signal: {output:?}"
            );
            assert_eq!(output.status.success(), success, "{args:?}\n{output:?}");
            output
        }

        pub fn output(&self, args: &[&str], config: &[(&str, &str)]) -> String {
            let output = self.run(args, config, true);
            assert!(output.stderr.is_empty(), "{args:?}: {output:?}");
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        }

        pub fn expect(&self, args: &[&str], config: &[(&str, &str)], expected: &str) {
            assert_eq!(self.output(args, config), expected, "{args:?}");
        }

        pub fn fail(&self, args: &[&str], config: &[(&str, &str)]) -> String {
            let output = self.run(args, config, false);
            assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
            String::from_utf8(output.stderr).unwrap()
        }

        #[cfg(feature = "sqlx-postgres")]
        fn create_postgres(&mut self) {
            let url = std::env::var("DATABASE_URL")
                .expect("requires a disposable PostgreSQL DATABASE_URL");
            let schema = format!(
                "cryptbox_e2e_{}",
                cryptbox::EncryptionKey::generate()
                    .unwrap()
                    .id()
                    .to_string()
                    .replace('-', "")
            );
            postgres_sql(&url, &format!("CREATE SCHEMA {schema}"));
            let mut scoped = url::Url::parse(&url).unwrap();
            let mut options = String::new();
            let mut parameters = Vec::new();
            for (key, value) in scoped.query_pairs() {
                if key == "options" {
                    options = value.into_owned();
                } else {
                    parameters.push((key.into_owned(), value.into_owned()));
                }
            }
            scoped.set_query(None);
            scoped
                .query_pairs_mut()
                .extend_pairs(parameters)
                .append_pair("options", &format!("{options} -c search_path={schema}"));
            self.database = scoped.into();
            self.postgres = Some((url, schema));
        }
    }

    #[cfg(feature = "sqlx-postgres")]
    fn postgres_sql(url: &str, query: &str) {
        use sqlx::Connection;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut connection = sqlx::PgConnection::connect(url).await.unwrap();
                sqlx::query(query).execute(&mut connection).await.unwrap();
                connection.close().await.unwrap();
            });
    }

    #[cfg(feature = "sqlx-postgres")]
    impl Drop for App {
        fn drop(&mut self) {
            if let Some((url, schema)) = &self.postgres {
                // Preserve the original assertion during unwinding, but fail an
                // otherwise successful test when its schema cannot be removed.
                let result = std::panic::catch_unwind(|| {
                    postgres_sql(url, &format!("DROP SCHEMA {schema} CASCADE"));
                });
                if !std::thread::panicking() {
                    if let Err(panic) = result {
                        std::panic::resume_unwind(panic);
                    }
                }
            }
        }
    }

    pub fn selection<'a>(encryption: &'a str, index: &'a str) -> [(&'static str, &'a str); 2] {
        [
            ("CRYPTBOX_ENCRYPTION", encryption),
            ("CRYPTBOX_INDEX", index),
        ]
    }
}
