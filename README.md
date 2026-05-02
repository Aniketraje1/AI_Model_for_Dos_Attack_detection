# AI Model for DoS Attack Detection

This project contains a notebook-driven intrusion detection workflow focused on DoS and related attack detection, along with Python helpers for live traffic monitoring and classification.

## Project files

- `Attacks Training.ipynb`: training and experimentation notebook.
- `live_classifier_stream.py`: watches captured traffic files and logs model predictions.
- `live_monitor_runner.py`: loads and runs the live monitor logic from the notebook.
- `how_to_run.txt`: Windows PowerShell workflow notes for training, capture, and live inference.

## Notes

- The live scripts currently use local Windows paths that may need to be updated on another machine.
- The UNSW-NB15 dataset files are not stored in this repository.
- Generated logs, live capture outputs, and temporary runtime artifacts are excluded from version control with `.gitignore`.
