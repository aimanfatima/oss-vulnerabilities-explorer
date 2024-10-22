# Open Source Software Vulnerabilities Explorer

Term: Fall Quarter 2024
Course: ECS 253A Computer & Information Security

Research Question: Are open-source software (OSS) projects truly free from vulnerabilities? Under what conditions do these vulnerabilities become exploitable, what the effects of such exploits are?

## Contribututors (Lexicographic order)

1. Aiman Fatima ([@aimanFatima](https://github.com/aimanfatima))
2. Isha Joglekar ([@ishajoglekar](https://github.com/ishajoglekar))
3. Ujjawal K. Panchal ([@Ujjawal-K-Panchal](https://github.com/Ujjawal-K-Panchal))

## Setup:
1. Make a `.env` file (ignored by git). Put in: `TOKEN='<your-github-pat>'`, `BASE_URL='https://api.github.com/search/code'`.
2. Install requirements inside virtual environment:
```python
python -m pip install --upgrade pip
python -m pip install virtualenv
python -m venv venv4chairdemon
source venv4chairdemon/bin/activate
python -m pip install -r requirements.txt
```

## Files:

1. `columbus.py`: The file which given a vulnerability scans OSS github repos for occurences.