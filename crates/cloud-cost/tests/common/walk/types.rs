use cloud_cost::fetch_error::FetchError;
use cloud_cost::fetch_model::Listing;


pub type Walked = (Result<Listing, FetchError>, usize);
