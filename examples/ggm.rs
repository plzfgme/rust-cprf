use cprf::ggm::GgmRCPrfMasterKey;
use generic_array::GenericArray;

fn main() {
    let key = GenericArray::from([0u8; 16]);
    let mk = GgmRCPrfMasterKey::new(key);
    let mk_output = mk.evaluate(2500);

    let ck = mk.constrained(2000, 3000);
    println!("{:?}", ck);
    let ck_output = ck.evaluate(2500).unwrap();
    println!("{:?}", ck_output);

    assert_eq!(mk_output, ck_output);

    for ck_output in ck.evaluate_all() {
        println!("{:?}", ck_output)
    }
}
