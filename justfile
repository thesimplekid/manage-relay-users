run-dev:
    RUST_LOG=WARN,manage_relay_users=DEBUG RUST_BACKTRACE=full cargo r
run-r:
    cargo build -r
    RUST_LOG=WARN,manage_relay_users=DEBUG ./target/release/manage_relay_users
check:
    cargo fmt --check --all
    cargo clippy --all
test:
    cargo test
fix: 
    cargo fmt
    cargo clippy --fix --allow-staged

commit:
    cargo fmt --check --all
    cargo clippy --all
    git commit