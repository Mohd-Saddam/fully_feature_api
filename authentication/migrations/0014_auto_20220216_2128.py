# Generated by Django 3.1.7 on 2022-02-16 15:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0013_auto_20220216_1617'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='auth_providers',
            field=models.CharField(default=None, max_length=255),
        ),
    ]
