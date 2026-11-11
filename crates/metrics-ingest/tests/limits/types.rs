use metrics_ingest::model::Limits;


pub type Setter = fn(&mut Limits, u64);


pub type Row = (&'static str, Setter, u64, u64);
