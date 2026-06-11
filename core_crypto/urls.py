"""
core_crypto/urls.py
===================
URL routing for the core_crypto API endpoints.

All endpoints are prefixed with /api/ (configured in the project-level urls.py).
"""

from django.urls import path

from core_crypto import views

app_name = 'core_crypto'

urlpatterns = [
    # POST /api/generate-keys/
    # Generates a fresh RSA-2048 key pair (public + private).
    path(
        'generate-keys/',
        views.generate_keys_view,
        name='generate-keys',
    ),

    # POST /api/sign-certificate/
    # Accepts image + private key → returns hash, signature (b64), entropy.
    path(
        'sign-certificate/',
        views.sign_certificate_view,
        name='sign-certificate',
    ),

    # POST /api/verify-certificate/
    # Accepts image + signature + public key → returns is_valid + avalanche.
    path(
        'verify-certificate/',
        views.verify_certificate_view,
        name='verify-certificate',
    ),

    # GET /api/history/ and POST /api/history/
    path(
        'history/',
        views.history_view,
        name='history',
    ),
]
