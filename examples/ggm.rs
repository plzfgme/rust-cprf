use cprf::ggm::Ggm64MasterKey;

fn main() {
    let key = [0u8; 16];
    let mk = Ggm64MasterKey::new_from_slice(&key);
    let mk_output = mk.evaluate(2500);

    let ck = mk.constrain(2000, 3000);
    println!("{:?}", ck);
    let ck_output = ck.evaluate(2500).unwrap();
    println!("{:?}", ck_output);

    assert_eq!(mk_output, ck_output);

    for ck_output in ck.evaluate_all() {
        println!("{:?}", ck_output)
    }
}
