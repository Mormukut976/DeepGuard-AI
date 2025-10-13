import pandas as pd
import numpy as np
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import os
import json

class PhishingDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_length=128):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = self.labels[idx]

        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )

        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }

class PhishingModelTrainer:
    def __init__(self):
        self.tokenizer = None
        self.model = None
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    def create_training_data(self):
        """Quality training data create karte hain"""
        phishing_emails = [
            "Congratulations! You won $1000. Click here to claim your prize",
            "URGENT: Your account will be suspended. Verify now",
            "Free iPhone! Click to claim your gift",
            "You have won a lottery! Claim $5000 now",
            "Security Alert: Your bank needs verification",
            "Get rich quick! Double your money today",
            "Your Amazon order has issues. Click to resolve",
            "Tax refund available! Claim money now",
            "Your social media was hacked. Click to secure",
            "Verify your PayPal account immediately",
            "You are selected for special offer",
            "Click to get free gift card",
            "Account locked for security. Click to unlock",
            "Update payment information now",
            "Your Netflix subscription expired. Renew now",
            "Win a new car! Click to enter",
            "Your package delivery failed. Click to reschedule",
            "Bank account compromised. Secure now",
            "Get free Bitcoin! Click to claim",
            "Your email storage is full. Upgrade now"
        ]
        
        legit_emails = [
            "Hi John, meeting scheduled for tomorrow at 3 PM",
            "Package delivery: Your order will arrive today",
            "Team lunch this Friday at 1 PM",
            "Your invoice is ready for download",
            "Project update: Features deployed successfully",
            "Weekly newsletter: Latest company updates",
            "Password reset confirmation",
            "Your subscription renews on January 15",
            "Thank you for purchase order #12345",
            "Reminder: Company meeting tomorrow",
            "Your support ticket has been resolved",
            "Software update available for your device",
            "Monthly report for October is available",
            "Invitation to company annual party",
            "Your job application is under review",
            "Project deadline extended to next week",
            "New features added to your account",
            "Your feedback is important to us",
            "Training session scheduled for next month",
            "System maintenance scheduled for Sunday"
        ]
        
        texts = phishing_emails + legit_emails
        labels = [1] * len(phishing_emails) + [0] * len(legit_emails)
        
        return texts, labels
    
    def train(self, epochs=5):
        """Simple training loop"""
        print("🔄 Preparing phishing model training...")
        
        # Training data
        texts, labels = self.create_training_data()
        
        # Initialize model and tokenizer
        self.tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
        self.model = DistilBertForSequenceClassification.from_pretrained('distilbert-base-uncased', num_labels=2)
        self.model.to(self.device)
        
        # Create dataset
        dataset = PhishingDataset(texts, labels, self.tokenizer)
        dataloader = DataLoader(dataset, batch_size=8, shuffle=True)
        
        # Training setup
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=2e-5)
        criterion = nn.CrossEntropyLoss()
        
        print("🚀 Starting training...")
        self.model.train()
        
        for epoch in range(epochs):
            total_loss = 0
            correct = 0
            total = 0
            
            for batch in dataloader:
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels = batch['labels'].to(self.device)
                
                optimizer.zero_grad()
                
                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
                loss = criterion(outputs.logits, labels)
                
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
                
                # Calculate accuracy
                _, predicted = torch.max(outputs.logits, 1)
                correct += (predicted == labels).sum().item()
                total += labels.size(0)
            
            accuracy = 100 * correct / total
            print(f'Epoch {epoch+1}/{epochs}, Loss: {total_loss/len(dataloader):.4f}, Accuracy: {accuracy:.2f}%')
    
    def save_model(self, model_path='./phishing_model'):
        """Model save karte hain"""
        os.makedirs(model_path, exist_ok=True)
        
        # Save model and tokenizer
        self.model.save_pretrained(model_path)
        self.tokenizer.save_pretrained(model_path)
        
        # Custom config save karte hain
        config = {
            "model_type": "distilbert",
            "task": "phishing-detection",
            "labels": {"0": "legitimate", "1": "phishing"}
        }
        
        with open(os.path.join(model_path, 'config.json'), 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Phishing model saved to {model_path}")

def train_phishing_model():
    """Main training function"""
    trainer = PhishingModelTrainer()
    trainer.train(epochs=5)
    trainer.save_model()
    return trainer

if __name__ == "__main__":
    train_phishing_model()
