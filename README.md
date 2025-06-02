# CMS Vulnerability Scanner

CMS Vulnerability Scanner is a simple, cross-platform tool designed to help security professionals and developers identify vulnerabilities in popular Content Management Systems like WordPress, Joomla, Drupal, Wix.

It's built with flexibility in mind, using a plugin-based structure and optional AI-assisted scanning, so you can tailor it to your needs.

## Features
- Detects known vulnerabilities in WordPress, Joomla, Drupal, Wix, and Shopify

- Plugin-based architecture for easy customization and extension

- Integrates with exploit databases

- Optional AI-assisted detection for smarter scanning

- Generates clean, detailed reports

- Compatible with Linux, Windows, and macOSS

## Installation

### Prerequisites
- Go 1.20 or newer

### Building from Source
Clone the repository and build the tool for your platform:

### clone the repository
   ```sh
  - git clone https://github.com/joe444-pnj/cmsvulnscan.git
- cd cmsvulnscan
```



#### Linux/macOS:
   ```sh
   go build -o cmsvulnscan ./cmd/cmsvulnscan
   ```

#### Windows:
   ```powershell
   go build -o cmsvulnscan.exe ./cmd/cmsvulnscan
   ```

## Usage

Run the scanner with:

#### Linux/macOS:
   ```sh
   ./cmsvulnscan --help
   ```

#### Windows:
   ```powershell
   .\cmsvulnscan.exe --help
   ```


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](LICENSE)
