use std::{
    cmp::Ordering::{Equal, Greater, Less},
    error::Error,
    iter::zip,
    marker::PhantomData,
};

use base64::{
    Engine,
    alphabet::Alphabet,
    engine::{GeneralPurpose, general_purpose::PAD},
};

use crate::models::User;

struct Data {
    data: Vec<u8>,
}

impl Data {
    fn from(data: String) -> Self {
        let length = data.len();
        let mut data = data.into_bytes();
        data.resize(length + 3 >> 2 << 2, 0);
        let mut length = Vec::from((length as u32).to_le_bytes());
        data.append(&mut length);
        Self { data }
    }

    fn len(&self) -> usize {
        self.data.len() >> 2
    }

    fn encrypt_iter(&mut self) -> DataEncryptIter {
        let start = self.data.as_mut_ptr();
        DataEncryptIter {
            cur_ptr: start,
            first_ptr: start,
            last_ptr: unsafe { start.add(self.data.len() - 4) },
            _p: PhantomData,
        }
    }

    fn base64(&self) -> String {
        let alphabet =
            Alphabet::new("LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA")
                .unwrap();
        GeneralPurpose::new(&alphabet, PAD).encode(&self.data)
    }
}

struct DataEncryptIter<'a> {
    cur_ptr: *mut u8,
    first_ptr: *mut u8,
    last_ptr: *mut u8,
    _p: PhantomData<&'a u32>,
}

impl<'a> Iterator for DataEncryptIter<'a> {
    type Item = (&'a mut u32, u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let cur_ptr = self.cur_ptr;
            let next_ptr = match cur_ptr.cmp(&self.last_ptr) {
                Less => cur_ptr.add(4),
                Equal => self.first_ptr,
                Greater => return None,
            };
            let prev_ptr = match cur_ptr.cmp(&self.first_ptr) {
                Less => unreachable!(),
                Equal => self.last_ptr,
                Greater => cur_ptr.sub(4),
            };
            self.cur_ptr = self.cur_ptr.add(4);
            Some((
                &mut *(cur_ptr as *mut u32),
                *(prev_ptr as *const u32),
                *(next_ptr as *const u32),
            ))
        }
    }
}

struct Key {
    key: [u32; 4],
}

impl Key {
    fn from(key: &str) -> Result<Self, Box<dyn Error>> {
        let mut k = Self { key: [0u32; 4] };
        for (kitem, keychunk) in zip(k.key.iter_mut(), key.as_bytes().chunks(4)) {
            *kitem = u32::from_le_bytes(keychunk.try_into()?);
        }
        Ok(k)
    }

    fn iter(&self, e: u32) -> KeyIter {
        KeyIter {
            key: &self.key,
            idx: e as usize,
            step: if e & 1 == 0 { 1 } else { 3 },
        }
    }
}

struct KeyIter<'a> {
    key: &'a [u32; 4],
    idx: usize,
    step: usize,
}

impl<'a> Iterator for KeyIter<'a> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        let k = self.key[self.idx & 3];
        self.idx += self.step;
        Some(k)
    }
}

pub fn encode(user: &User, ac_id: u32, token: &str) -> Result<String, Box<dyn Error>> {
    let key = Key::from(token)?;
    let data = format!(
        "{{\"acid\":{},\"enc_ver\":\"srun_bx1\",\"ip\":\"\",\"password\":\"{}\",\"username\":\"{}\"}}",
        ac_id, user.password, user.username
    );
    let mut data = Data::from(data);
    let q = 6 + 52 / data.len();
    let mut d: u32 = 0;
    for _ in 0..q {
        d = d.wrapping_add(0x9E3779B9);
        let e = d >> 2 & 3;
        for ((cur, prev, next), key) in zip(data.encrypt_iter(), key.iter(e)) {
            *cur = cur
                .wrapping_add(prev >> 5 ^ next << 2)
                .wrapping_add(prev << 4 ^ next >> 3 ^ d ^ next)
                .wrapping_add(key ^ prev);
        }
    }
    Ok(format!("{{SRBX1}}{}", data.base64()))
}
