


pub struct VaultyHeader {
    magic: u8
}

impl VaultyHeader {
    pub fn new(mag: u8) -> Self {
        return VaultyHeader{magic: mag};
    }
}