from django.db import models
from authentication.models import User

# Create your models here.
class Income(models.Model):
    SOURCE_OPTIONS=[
        ('SALARY','SALARY'),
        ('BUSINESS','BUSINESS'),
        ('SIDE-HUSTLES','SIDE-HUSTLES'),
        ('OTHER','OTHER')]
    
    source = models.CharField(choices=SOURCE_OPTIONS,max_length=255)
    amount = models.DecimalField(max_digits=10,decimal_places=2,max_length=255)
    description = models.TextField()
    owner = models.ForeignKey(to=User, on_delete=models.CASCADE,help_text="user id")
    date = models.DateField(null=False, blank=False)
    # created_at = models.DateTimeField(auto_now_add=True)
    # updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering: ['-date']
        db_table = 'income'

    def __str__(self):
        return str(self.owner)+'s income'

