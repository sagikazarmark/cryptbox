#[derive(cryptbox::BlindIndexSpec)]
#[blind_index(id = "not a uuid", value = String, bits = 300)]
#[blind_index(bits = 32, seal, query = str, normalize = normalize)]
struct EveryMistake;

fn main() {}
