
![Logo](https://files.catbox.moe/9y029x.png)



# CMS Vulnerability Scanner

[![Issues](https://img.shields.io/github/issues/joe444-pnj/cmsvulnscan)](https://github.com/joe444-pnj/cmsvulnscan/issues)

[![Pull Requests](https://img.shields.io/github/issues-pr/joe444-pnj/cmsvulnscan)](https://github.com/joe444-pnj/cmsvulnscan/pulls)

CMS Vulnerability Scanner is a simple, cross-platform tool designed to help security professionals and developers identify vulnerabilities in popular Content Management Systems like WordPress, Joomla, Drupal, Wix, and Shopify. It’s built with flexibility in mind, using a plugin-based structure and optional AI-assisted scanning, so you can tailor it to your needs.

## Features
- Detects known vulnerabilities in WordPress, Joomla, Drupal, Wix.
- Plugin-based architecture for easy customization and extension
- Integrates with exploit databases
- Optional AI-assisted detection for smarter scanning
- Generates clean, detailed reports
- Compatible with Linux, Windows, and macOS

##  Installation

### Prerequisites
[![Go Version](https://img.shields.io/badge/go-1.20%2B-blue)](https://go.dev/dl)
- Go 1.20 or newer — [Download Go](https://go.dev/dl)


### Clone the Repository
```bash
git clone https://github.com/joe444-pnj/cmsvulnscan.git
cd cmsvulnscan
```
# Build from Source

On Linux/macOS:
```
go build -o cmsvulnscan ./cmd/cmsvulnscan
```
On Windows
```
go build -o cmsvulnscan.exe ./cmd/cmsvulnscan
```

## Usage

On Linux/macOS
```
./cmsvulnscan --help
```
On Windows
```
.\cmsvulnscan.exe --help
```
## Contributing

Pull requests are welcome! For major changes, please open an issue to discuss what you would like to change. [![Issues](https://img.shields.io/github/issues/joe444-pnj/cmsvulnscan)](https://github.com/joe444-pnj/cmsvulnscan/issues)


## License
[![License](https://img.shields.io/github/license/joe444-pnj/cmsvulnscan)](LICENSE)
