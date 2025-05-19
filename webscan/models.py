from django.db import models

class CNVDEntry(models.Model):
    title = models.CharField(max_length=255)
    link = models.URLField()
    summary = models.TextField()

    def __str__(self):
        return self.title
