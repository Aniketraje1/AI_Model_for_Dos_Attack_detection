# AI Model for DoS Attack Detection

This project demonstrates a machine learning workflow for detecting Denial of Service (DoS) traffic from captured network data and using the trained model in a live monitoring setup.

## Project Overview

The main goal of this project is to distinguish DoS traffic from non-DoS traffic using supervised learning. The workflow combines:

- labeled live traffic datasets for DoS and non-DoS behavior
- a training notebook that cleans data, engineers features, compares models, and saves the best model
- a live detection pipeline that monitors packet captures and logs confirmed alerts
- a small Docker/FastAPI lab used to generate and validate live traffic during testing

## Repository Contents

- `dos_detection_training_notebook.ipynb`: trains and evaluates the binary DoS detection model
- `howtorun2.txt`: step-by-step instructions for running the live demo workflow
- `live_dos_current.csv`: labeled DoS traffic dataset used for training/testing
- `live_non_ddos_current.csv`: labeled non-DoS traffic dataset used for training/testing

## What the Notebook Does

The training notebook is designed to be beginner-friendly while still following practical machine learning steps:

- loads large CSV files in chunks
- labels DoS traffic as `1` and non-DoS traffic as `0`
- removes obvious identifier and timestamp-style columns
- handles missing and infinite values
- performs feature engineering when traffic-rate features are available
- compares multiple classification models including Random Forest, Logistic Regression, and KNN
- selects a final model using an untouched test split and saves it for reuse

## Live Detection Workflow

The live pipeline uses Wireshark capture files together with a trained model to monitor traffic in near real time. The detector also applies additional behavior checks such as packet-rate and repeated-target thresholds to reduce false positives and confirm meaningful DoS-style activity before logging alerts.

## Tools and Technologies

- Python
- pandas
- numpy
- scikit-learn
- joblib
- Wireshark (`dumpcap` / `tshark`)
- Docker
- FastAPI

## Project Evidence

This repository shows direct evidence of the project through:

- the full training notebook
- the labeled live traffic datasets
- the run instructions for reproducing the workflow
- the live detection pipeline used during project testing

## How to Run

The quickest reference is `howtorun2.txt`. In summary, the workflow is:

1. start packet capture and the Docker-based lab traffic
2. run the live DoS detector with the trained model
3. watch the detection log for confirmed alerts
4. stop the capture and Docker services when finished

## Public Project Summary

This project applies machine learning to a cybersecurity problem by training a binary classifier for DoS detection and connecting that model to a live monitoring workflow. It demonstrates data preparation, model training, model comparison, live inference, and reproducible testing in a small lab environment.
