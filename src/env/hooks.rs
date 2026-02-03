use crate::env::loader::LoaderEnv;

pub fn init(loader_env: &mut LoaderEnv) {
    loader_env.set_if_unset("print_delay", "0");
    loader_env.set_if_unset("currdev", "");
}
