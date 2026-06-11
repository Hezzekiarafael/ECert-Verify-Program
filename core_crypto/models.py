from django.db import models

class VerificationHistory(models.Model):
    file_name = models.CharField(max_length=255)
    bit_similarity = models.CharField(max_length=50)
    avalanche_effect = models.CharField(max_length=50)
    bit_diffusion = models.CharField(max_length=50)
    verify_time = models.CharField(max_length=50)
    status = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.file_name} - {self.status}"
