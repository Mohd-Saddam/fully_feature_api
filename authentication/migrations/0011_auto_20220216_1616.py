# Generated by Django 3.1.7 on 2022-02-16 10:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0010_user_auth_providers'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='auth_providers',
            field=models.CharField(blank=True, default=None, max_length=255),
        ),
    ]