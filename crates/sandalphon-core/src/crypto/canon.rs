use alloc::vec::Vec;

pub trait Canonicalisable {
    fn canon_into(&self, output: &mut Vec<u8>);

    fn canon(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.canon_into(&mut output);
        output
    }
}
