"""
core_crypto/tests_api.py
========================
Integration tests for the E-Certificate Verification System API.

Validates the following endpoints:
    1. POST /api/generate-keys/
    2. POST /api/sign-certificate/
    3. POST /api/verify-certificate/
"""

import base64
import io
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.core.files.uploadedfile import SimpleUploadedFile

class CryptoAPITests(APITestCase):
    """Tests for the cryptographic API endpoints."""

    def test_generate_keys(self):
        """Test the key generation endpoint."""
        url = reverse('core_crypto:generate-keys')
        response = self.client.post(url, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')
        self.assertIn('private_key', response.data['data'])
        self.assertIn('public_key', response.data['data'])
        self.assertIn('execution_time_ms', response.data)
        self.assertEqual(response.data['data']['key_size_bits'], 2048)

    def test_sign_and_verify_workflow(self):
        """Test the full sign-then-verify workflow via API."""
        
        # 1. Generate keys
        gen_url = reverse('core_crypto:generate-keys')
        gen_response = self.client.post(gen_url, format='json')
        private_key = gen_response.data['data']['private_key']
        public_key = gen_response.data['data']['public_key']

        # 2. Sign certificate
        sign_url = reverse('core_crypto:sign-certificate')
        image_content = b"Fake Image Content \x89PNG\r\n\x1a\n"
        image_file = SimpleUploadedFile("cert.png", image_content, content_type="image/png")
        
        sign_data = {
            'image': image_file,
            'private_key': private_key
        }
        
        sign_response = self.client.post(sign_url, sign_data, format='multipart')
        
        self.assertEqual(sign_response.status_code, status.HTTP_200_OK)
        self.assertIn('sha256_hash', sign_response.data['data'])
        self.assertIn('digital_signature_b64', sign_response.data['data'])
        self.assertIn('entropy_analysis', sign_response.data['data'])
        
        signature_b64 = sign_response.data['data']['digital_signature_b64']
        original_hash = sign_response.data['data']['sha256_hash']

        # 3. Verify certificate (Valid)
        verify_url = reverse('core_crypto:verify-certificate')
        image_file_verify = SimpleUploadedFile("cert.png", image_content, content_type="image/png")
        
        verify_data = {
            'image': image_file_verify,
            'signature': signature_b64,
            'public_key': public_key,
            'original_hash': original_hash
        }
        
        verify_response = self.client.post(verify_url, verify_data, format='multipart')
        
        self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
        self.assertTrue(verify_response.data['data']['is_valid'])
        self.assertEqual(verify_response.data['data']['avalanche_analysis']['avalanche_effect_pct'], 0.0)

        # 4. Verify certificate (Tampered image)
        tampered_content = b"Fake Image Content \x89PNG\r\n\x1a\nTAMPERED"
        image_file_tampered = SimpleUploadedFile("cert.png", tampered_content, content_type="image/png")
        
        verify_data_tampered = {
            'image': image_file_tampered,
            'signature': signature_b64,
            'public_key': public_key,
            'original_hash': original_hash
        }
        
        tampered_response = self.client.post(verify_url, verify_data_tampered, format='multipart')
        
        self.assertEqual(tampered_response.status_code, status.HTTP_200_OK)
        self.assertFalse(tampered_response.data['data']['is_valid'])
        # Avalanche effect should be significantly > 0
        self.assertGreater(tampered_response.data['data']['avalanche_analysis']['avalanche_effect_pct'], 10.0)
