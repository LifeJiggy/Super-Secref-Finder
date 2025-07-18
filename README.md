# Super Secref Finder


**Super Secref Finder** is an advanced regex-based security scanner designed to discover sensitive information like API keys, passwords, tokens, and other secrets exposed within web applications and their associated JavaScript files. It leverages a comprehensive collection of regular expressions and employs multi-threading for efficient scanning of large websites.

## Features

* **Advanced Regex Engine:** Utilizes a powerful regex engine with customizable patterns for precise secret detection.  Includes a curated list of common sensitive patterns (e.g., AWS keys, JWT tokens, various API keys).
* **Multi-threaded Scanning:** Employs multi-threading to significantly speed up the scanning process, allowing for efficient analysis of large websites and numerous JavaScript files.
* **JavaScript File Analysis:**  Automatically extracts and scans linked JavaScript files for exposed secrets, expanding the scope of the scan beyond the main HTML content.
* **Interactive Menu:** Provides a user-friendly interactive menu for easy configuration of target URL, thread count, request delay, and verbose output options.
* **Contextualized Findings:** Presents findings with surrounding context to aid in quick verification and analysis of potential vulnerabilities.
* **False Positive Filtering:** Includes a mechanism to log and filter potential false positives, improving the accuracy of the results.
* **JSON Output:** Saves scan results in a structured JSON format for easy integration with other security tools and workflows.
* **Summary Reporting:** Generates a summary of findings categorized by secret type for a quick overview of discovered vulnerabilities.
* **Customizable Confidence Threshold:** Allows adjusting the confidence threshold for reported findings, balancing sensitivity and precision.
* **Rate Limit Handling:** Implements dynamic delay adjustments to handle rate limiting imposed by target servers.
* **User-Agent Spoofing:** Uses a common user agent to mimic normal browser behavior and avoid detection.
* **Error Handling and Retries:** Includes robust error handling and retry mechanisms to ensure scan completion even in the face of network issues.
* **Verbose Output:** Offers a verbose output mode for detailed information on the scanning process.
* **Cross-Platform Compatibility:** Designed to run on various operating systems.


## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/LifeJiggy/Super-Secref-Finder.git


2. Install dependencies:

    bash
    pip install -r requirements.txt


3. (Optional) Create a virtual environment: It's recommended to use a    virtual environment to manage dependencies.
    bash
    python3 -m venv .venv
    source .venv/bin/activate  # On Linux/macOS
.   venv\Scripts\activate  # On Windows

## Usage:

1. Run the scanner:
    bash
    python Regex_patterns.py 

2. Follow the interactive menu:

    * Enter the target URL.
    * Specify the number of threads (1-600).
    * Set the delay between requests (1-100 seconds).
    * Choose verbose output (y/n).

3. Review the results: The findings will be saved to findings.json and a summary will be displayed in the console.

## Configuration
    The sensitive_patterns.py file contains the regular expressions used for secret detection. You can customize these patterns or add new ones as needed. Ensure that the validate_pattern function in sensitive_patterns.py is updated accordingly to minimize false positives.

## Contributing
    Contributions are welcome! Please feel free to submit pull requests for bug fixes, new features, or improvements to existing patterns.

## License
    This project is licensed under the
    MIT License


## Disclaimer
    This tool is intended for security testing and research purposes only. Use it responsibly and ethically. Unauthorized access to computer systems is illegal. The developers are not responsible for any misuse of this tool.

## Contact
    ArkhAngelLifeJiggy -
    GITHUB:
    https://github.com/LifeJiggy