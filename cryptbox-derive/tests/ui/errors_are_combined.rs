#[derive(cryptbox::BlindIndexSpec)]
#[cryptbox(id = "not a uuid", value = String, bits = 300)]
#[cryptbox(bits = 32, field, query = str, normalize = normalize)]
struct EveryMistake;

fn main() {}
