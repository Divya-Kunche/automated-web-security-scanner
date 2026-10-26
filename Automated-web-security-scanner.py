"""
Automated Web Security Scanner Using Python

An educational application that checks an HTTPS website
for selected security headers and basic CORS configuration.

Requirements:
Python 3 with Tkinter support.
No external Python packages are required.

Use only on websites you own or have permission to test.
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from datetime import datetime
import ssl


SECURITY_HEADERS = {
    "Strict-Transport-Security":
        "Helps browsers use HTTPS for future connections.",

    "Content-Security-Policy":
        "Helps reduce certain content-injection risks.",

    "X-Content-Type-Options":
        "Helps prevent MIME-type sniffing.",

    "X-Frame-Options":
        "Helps control whether a page can be embedded in frames.",

    "Referrer-Policy":
        "Controls referrer information sent by browsers."
}


def validate_url(url):
    url = url.strip()

    if not url:
        raise ValueError("Please enter a website URL.")

    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme.lower() != "https":
        raise ValueError("Please enter an HTTPS website URL.")

    if not parsed.hostname:
        raise ValueError("Please enter a valid website URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")

    return url


def scan_website(url):
    request = Request(
        url,
        headers={
            "User-Agent": "Educational-Web-Security-Scanner/1.0"
        }
    )

    context = ssl.create_default_context()

    try:
        with urlopen(
            request, timeout=12, context=context
        ) as response:
            status = response.status
            final_url = response.geturl()
            headers = response.headers

    except HTTPError as error:
        status = error.code
        final_url = error.geturl()
        headers = error.headers

    except (URLError, TimeoutError, OSError, ssl.SSLError) as error:
        raise RuntimeError(
            "Unable to connect to the website.\n"
            "Check the URL and your internet connection.\n"
            + str(error)
        ) from error

    header_map = {
        name.lower(): value.strip()
        for name, value in headers.items()
    }

    report = [
        "AUTOMATED WEB SECURITY SCANNER",
        "=" * 40,
        "Requested URL: " + url,
        "Final URL: " + final_url,
        "HTTP Status: " + str(status),
        "Scan Time: " + datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "",
        "SECURITY HEADER CHECKS",
        "-" * 40
    ]

    for header, recommendation in SECURITY_HEADERS.items():
        value = header_map.get(header.lower())

        if value:
            report.append("[PRESENT] " + header)
            report.append("Value: " + value)
        else:
            report.append("[MISSING] " + header)
            report.append("Recommendation: " + recommendation)

        report.append("")

    report.extend([
        "BASIC CORS REVIEW",
        "-" * 40
    ])

    origin = header_map.get("access-control-allow-origin")
    credentials = header_map.get(
        "access-control-allow-credentials"
    )

    if origin:
        report.append(
            "Access-Control-Allow-Origin: " + origin
        )

        if origin == "*":
            report.append(
                "Review whether allowing every origin is intended."
            )
    else:
        report.append(
            "Access-Control-Allow-Origin: Not present"
        )

    if credentials:
        report.append(
            "Access-Control-Allow-Credentials: " + credentials
        )

        if credentials.lower() == "true" and origin == "*":
            report.append(
                "Review: Browsers do not accept wildcard origins "
                "for credentialed CORS requests."
            )
    else:
        report.append(
            "Access-Control-Allow-Credentials: Not present"
        )

    report.extend([
        "",
        "IMPORTANT NOTES",
        "-" * 40,
        "Missing headers do not automatically mean a website "
        "is vulnerable.",
        "CORS security depends on the complete server configuration.",
        "This is a basic response-header scanner, not a full "
        "penetration-testing tool.",
        "Use only on websites you own or have permission to test."
    ])

    return "\n".join(report)


class SecurityScannerApp:

    def __init__(self, root):
        self.root = root
        self.root.title("Automated Web Security Scanner")
        self.root.geometry("750x600")

        heading = tk.Label(
            root,
            text="Automated Web Security Scanner",
            font=("Arial", 16, "bold")
        )
        heading.pack(pady=12)

        tk.Label(
            root,
            text="Enter an HTTPS website URL:"
        ).pack(anchor="w", padx=15)

        self.url_entry = tk.Entry(root, font=("Arial", 11))
        self.url_entry.pack(fill="x", padx=15, pady=7)
        self.url_entry.insert(0, "https://example.com")

        self.url_entry.bind(
            "<Return>",
            lambda event: self.run_scan()
        )

        buttons = tk.Frame(root)
        buttons.pack(pady=5)

        self.scan_button = tk.Button(
            buttons,
            text="Scan Website",
            command=self.run_scan
        )
        self.scan_button.pack(side="left", padx=5)

        tk.Button(
            buttons,
            text="Save Report",
            command=self.save_report
        ).pack(side="left", padx=5)

        tk.Button(
            buttons,
            text="Clear Results",
            command=self.clear_results
        ).pack(side="left", padx=5)

        self.results = scrolledtext.ScrolledText(
            root,
            wrap=tk.WORD,
            font=("Consolas", 10)
        )
        self.results.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=10
        )

        self.results.insert(
            tk.END,
            "Welcome!\nEnter a website URL and click Scan Website."
        )

    def run_scan(self):
        try:
            url = validate_url(self.url_entry.get())
        except ValueError as error:
            messagebox.showerror("Invalid URL", str(error))
            return

        self.scan_button.config(
            state=tk.DISABLED,
            text="Scanning..."
        )
        self.root.update_idletasks()

        try:
            report = scan_website(url)

            self.results.delete("1.0", tk.END)
            self.results.insert(tk.END, report)

        except RuntimeError as error:
            messagebox.showerror("Scan Failed", str(error))

        finally:
            self.scan_button.config(
                state=tk.NORMAL,
                text="Scan Website"
            )

    def save_report(self):
        from tkinter import filedialog

        report = self.results.get("1.0", tk.END).strip()

        if not report:
            messagebox.showinfo(
                "No Report",
                "Run a scan before saving the report."
            )
            return

        path = filedialog.asksaveasfilename(
            title="Save Security Scan Report",
            defaultextension=".txt",
            initialfile="security_scan_report.txt",
            filetypes=[("Text Files", "*.txt")]
        )

        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write(report + "\n")

            messagebox.showinfo(
                "Success",
                "Security report saved successfully."
            )

        except OSError as error:
            messagebox.showerror(
                "Save Failed",
                str(error)
            )

    def clear_results(self):
        self.results.delete("1.0", tk.END)
        self.results.insert(
            tk.END,
            "Results cleared. Enter a URL to start a new scan."
        )


def main():
    root = tk.Tk()
    SecurityScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
