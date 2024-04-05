apt update
apt upgrade -y

apt install -y pkg-config openssl-sys libssl-dev libmariadb-dev-compat libmariadb-dev 

snap install rustup

rustup default stable --classic

cargo run --features sqlite --release