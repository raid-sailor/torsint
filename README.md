# OSINT Tool for IP and Domain Analysis

This OSINT tool is designed for CTI analysts to perform IP and domain analysis. The tool utilizes multiple API sources, including GreyNoise, Shodan, URLScan, and WHOIS, to gather data on a given IP or domain. 

## Installation

To install the required Python packages, please run the following command:

```
pip3 install -r requirements.txt
```

## API Tokens

To use the tool, you must provide API tokens for the following sources in a `.env` file:

```
GREYNOISE=''
SHODAN=''
URLSCAN=''
WHOIS=''
```

Please replace the empty strings with your API tokens for each respective source.

## Usage

To use the tool, add the path of the `torsint` script to your system's `PATH` environment variable. You can do this by running the following command in your terminal:

```
export PATH=$PATH:/path/to/torsint
```

Replace `/path/to/torsint` with the actual path of the `torsint` script on your machine.

Once you have added the `torsint` script to your `PATH`, you can run the tool from the command line using the following command:

```
torsint <ip/domain>
```

Replace `<ip/domain>` with the IP or domain you wish to analyze. 

The tool will gather data from the specified API sources and present the results in a user-friendly format.

## Contributing

We welcome contributions to this project! To contribute, please fork this repository and submit a pull request. 

Please ensure that your code adheres to the PEP 8 style guide and includes appropriate documentation. 

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.
