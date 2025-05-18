# 🍗 KFC Registration Bot

A Python script for automating KFC account registration and voucher checking.

## Features

- 🔐 Automatic account registration
- 📱 Phone number formatting support
- 📧 Random email generation
- 🔑 Fixed password and PIN
- 🎟️ Voucher checking
- 💾 Account information saving

## Requirements

- Python 3.7 or higher
- Required packages (install using `pip install -r requirements.txt`):
  - requests
  - Faker
  - pycryptodome

## Installation

1. Clone this repository or download the files
2. Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the script:
```bash
python register.py
```

2. Follow the prompts:
   - Enter your phone number (supports various formats)
   - Enter the OTP received via SMS
   - The script will automatically:
     - Generate random user information
     - Set up the account with default credentials
     - Check available vouchers
     - Save account information to `akun.txt`

## Account Information

- Default Password: `123Qwerty@`
- Default PIN: `112233`
- Email Format: `firstname.lastname@mailcuk.com`

## Output Files

- `akun.txt`: Contains registered account information in the format:
  ```
  phone|password|pin|voucher_expiry
  ```

## Notes

- The script uses a fixed device ID and notification token
- All accounts are registered with the same default password and PIN
- Voucher information is automatically saved to `akun.txt` 