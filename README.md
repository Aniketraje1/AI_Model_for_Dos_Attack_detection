# AI Model for DoS Attack Detection

This project contains a notebook-driven intrusion detection workflow focused on DoS and related attack detection using the UNSW-NB15 dataset, along with Python helpers for live traffic monitoring and classification.

## Project files

- `Attacks Training.ipynb`: training and experimentation notebook.
- `live_classifier_stream.py`: watches captured traffic files and logs model predictions.
- `live_monitor_runner.py`: loads and runs the live monitor logic from the notebook.
- `how_to_run.txt`: Windows PowerShell workflow notes for training, capture, and live inference.
- `NUSW-NB15_features.csv`: feature reference file for the dataset.
- `UNSW_NB15_training-set.csv`: training split of the UNSW-NB15 dataset.
- `UNSW_NB15_testing-set.csv`: testing split of the UNSW-NB15 dataset.

## Notes

- The live scripts currently use local Windows paths that may need to be updated on another machine.
- Generated logs, live capture outputs, and temporary runtime artifacts are excluded from version control with `.gitignore`.
