use rocket_contrib::databases::redis;

#[database("session_db")]
pub struct SessionDbConn(redis::Connection);
