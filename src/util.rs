use std::fs::File;
use std::io::BufReader;
use std::io::prelude::Read;

pub fn read_file(file_path: &String) -> Option<String> {
    match File::open(file_path) {
        Ok (file) => { 
            let mut buf_reader = BufReader::new(file);
            let mut contents = String::new();
            let res = buf_reader.read_to_string(&mut contents);
            match res {
                Ok(_) => {
                    return Some(contents);
                }
                Err(err) => eprintln!("Could not read JSON file: {}", err),
            }
        },
        Err(err) => eprintln!("Could not open JSON file: {}", err),
    }
    None
}

pub fn ordered_tuple_key<T: std::cmp::PartialOrd>(key0: T, key1: T) -> (T, T) {
    if key0 < key1 { 
        return (key0, key1);
    } else { 
        return (key1, key0);
    }
}
