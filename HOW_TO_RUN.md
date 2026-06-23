# AI-Based Mobile Network Intrusion Detection — How to Run

Hi! This is a quick guide to open and use the project. You don't need to know any
coding — just follow along.

---

## What it does

It's a web dashboard that uses AI to spot intrusions (attacks) in mobile network
traffic. There are two parts — the dashboard you see and the AI engine behind it —
but don't worry, they both start together with a single click.

---

## What to install first (just once)

The computer needs these two free programs:

- **Node.js** — get it from https://nodejs.org/ (the "LTS" version is fine)
- **Python** — get it from https://www.python.org/ — and please **tick
  "Add Python to PATH"** while installing.

If they're already on the computer, you can skip this.

---

## Starting it up

1. Open the project folder.
2. Double-click **`START.bat`**.
3. A black window pops up with some setup text — give it a few minutes the first
   time, since it's getting everything ready. After that it's quick.
4. When it's done, the dashboard **opens in your browser by itself**.

Just leave that black window open while you work — it's running the engine.

---

## Using it

In the browser you can watch live network activity, upload a traffic capture file
to analyse, and see what the AI flags as normal or suspicious.

If the browser tab ever closes, just reopen this address while the black window is
still running:

> **http://127.0.0.1:5003**

---

## Stopping it

Close the black window, or press `Ctrl + C` inside it. That shuts everything down.

---

**In short:** install Node.js + Python once → double-click `START.bat` → the
dashboard opens → close the black window when you're done.
