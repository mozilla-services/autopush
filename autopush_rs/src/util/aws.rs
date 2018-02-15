use std::time::Duration;

use reqwest;

/// Fetch the EC2 instance-id
pub fn get_ec2_instance_id() -> reqwest::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;
    client
        .get("http://169.254.169.254/latest/meta-data/instance-id")
        .send()?
        .error_for_status()?
        .text()
}
