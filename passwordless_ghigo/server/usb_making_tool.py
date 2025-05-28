from flask import Flask, request, jsonify
import json
import base64
import os
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

KEY_GEN_PATH = "genera_chiavi.py"  # Path to key generation script