# Jim Knochelmann's Portfolio Site

This repository contains the source code for my personal website at [https://uncle13013.github.io/](https://uncle13013.github.io/).

## Running Locally

1. **Install dependencies:**
   - Make sure you have Ruby, Bundler, and Jekyll installed.
   - Install project dependencies:
     ```bash
     bundle install
     ```

2. **Serve the site locally:**
   - Run the Jekyll server, binding to all interfaces (for mobile testing):
     ```bash
     bundle exec jekyll serve --host 0.0.0.0 --port 4000
     ```
   - Visit [http://localhost:4000](http://localhost:4000) on your computer.
   - To test on your phone, use your computer's LAN IP (e.g., `http://192.168.0.x:4000`).

3. **Live Reload:**
   - The site will automatically reload when you save changes to files.

## Deployment

- **Automatic:** Any changes pushed to the `main` branch are automatically deployed and go live at [https://uncle13013.github.io/](https://uncle13013.github.io/) via GitHub Pages.

---

For questions or issues, open an issue or contact me directly.
