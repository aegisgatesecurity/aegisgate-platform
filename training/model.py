# SPDX-License-Identifier: Apache-2.0
# =========================================================================
# AegisGate Platform - Char CNN-BiLSTM Threat Detection Model Definition
# =========================================================================
#
# Architecture: Character-level CNN-BiLSTM with Attention
# Parameters: 2-5M (~800KB ONNX)
# Input: [batch, 128] int32 (ASCII character IDs, PAD=0, UNK=1)
# Output: [batch, 1] float32 (sigmoid threat score [0, 1])
#
# This model must EXACTLY match the Go normalizer in pkg/ml/normalizer.go:
#   - MaxSeqLen = 128
#   - VocabSize = 128 (ASCII 0-127)
#   - PadID = 0
#   - UnkID = 1
#   - Printable ASCII [32-126] mapped directly
#   - Non-printable/non-ASCII mapped to UNK (1)
#
# The ONNX export must produce:
#   - Input:  "input"    [1, 128] int32
#   - Output: "threat_score" [1] float32
#
# Integration: supplementary layer behind regex, never overrides regex.
# Threshold: calibrated for 0% FPR on benign traffic.
#
# =========================================================================

import torch
import torch.nn as nn
import torch.nn.functional as F
import math


# =========================================================================
# Constants (MUST match pkg/ml/normalizer.go)
# =========================================================================
MAX_SEQ_LEN = 128      # Maximum input sequence length
VOCAB_SIZE = 128        # ASCII vocabulary (0-127)
PAD_ID = 0              # Padding token
UNK_ID = 1              # Unknown character token
EMBEDDING_DIM = 64      # Character embedding dimension
CONV_FILTERS = 256      # Number of CNN filters per kernel size
CONV_KERNELS = [3, 5, 7]  # CNN kernel sizes (parallel branches)
LSTM_HIDDEN = 128       # BiLSTM hidden size (per direction)
LSTM_OUTPUT = 256       # BiLSTM total output (2 * hidden for bidirectional)
ATTENTION_DIM = 256     # Attention layer dimension
DENSE_HIDDEN = 64       # Dense layer hidden units
DROPOUT_RATE = 0.3      # Dropout rate


# =========================================================================
# Attention Layer
# =========================================================================
class Attention(nn.Module):
    """Learned attention over BiLSTM outputs.
    
    Computes a weighted sum of BiLSTM outputs where weights are
    learned from the hidden states themselves. This allows the model
    to focus on the most threat-relevant parts of the input.
    """

    def __init__(self, hidden_dim: int):
        super().__init__()
        self.attention = nn.Linear(hidden_dim, 1)

    def forward(self, lstm_output: torch.Tensor) -> torch.Tensor:
        """
        Args:
            lstm_output: [batch, seq_len, hidden_dim]
        Returns:
            context: [batch, hidden_dim] — weighted sum of lstm_output
        """
        # Compute attention weights
        attention_weights = F.softmax(
            self.attention(lstm_output).squeeze(-1),  # [batch, seq_len]
            dim=-1
        )
        # Weighted sum
        context = torch.bmm(
            attention_weights.unsqueeze(1),  # [batch, 1, seq_len]
            lstm_output                        # [batch, seq_len, hidden_dim]
        ).squeeze(1)  # [batch, hidden_dim]
        return context


# =========================================================================
# Char CNN-BiLSTM Model
# =========================================================================
class ThreatCNNBiLSTM(nn.Module):
    """Character-level CNN-BiLSTM with Attention for threat detection.
    
    Architecture:
        Input: [batch, 128] int32 (ASCII char IDs)
        → Embedding(128 vocab → 64 dim)
        → 3 parallel Conv1D branches (kernel_sizes=[3,5,7], filters=256)
        → Concatenate conv outputs → [batch, seq_len, 768]
        → BiLSTM(128 hidden) → [batch, seq_len, 256]
        → Attention → [batch, 256]
        → Dense(64, ReLU) → Dropout(0.3) → Dense(1, Sigmoid) → [batch, 1]
    
    Total parameters: ~3-4M
    ONNX export size: ~800KB
    """

    def __init__(
        self,
        vocab_size: int = VOCAB_SIZE,
        embedding_dim: int = EMBEDDING_DIM,
        conv_filters: int = CONV_FILTERS,
        conv_kernels: list = None,
        lstm_hidden: int = LSTM_HIDDEN,
        dense_hidden: int = DENSE_HIDDEN,
        dropout_rate: float = DROPOUT_RATE,
        max_seq_len: int = MAX_SEQ_LEN,
    ):
        super().__init__()

        if conv_kernels is None:
            conv_kernels = CONV_KERNELS

        self.vocab_size = vocab_size
        self.embedding_dim = embedding_dim
        self.conv_filters = conv_filters
        self.conv_kernels = conv_kernels
        self.lstm_hidden = lstm_hidden
        self.dense_hidden = dense_hidden
        self.dropout_rate = dropout_rate
        self.max_seq_len = max_seq_len

        # 1. Character embedding: 128 vocab → 64 dim
        self.embedding = nn.Embedding(
            num_embeddings=vocab_size,
            embedding_dim=embedding_dim,
            padding_idx=PAD_ID  # PAD tokens get zero embedding
        )

        # 2. Parallel Conv1D branches with different kernel sizes
        self.conv_branches = nn.ModuleList([
            nn.Conv1d(
                in_channels=embedding_dim,
                out_channels=conv_filters,
                kernel_size=k,
                padding=k // 2,  # Same-padding to preserve sequence length
            )
            for k in conv_kernels
        ])

        # Total conv output channels: conv_filters * len(conv_kernels)
        conv_total = conv_filters * len(conv_kernels)

        # 3. Batch normalization after conv (helps training stability)
        self.batch_norm = nn.BatchNorm1d(conv_total)

        # 4. BiLSTM: processes sequence in both directions
        self.lstm = nn.LSTM(
            input_size=conv_total,
            hidden_size=lstm_hidden,
            num_layers=2,
            batch_first=True,
            bidirectional=True,
            dropout=0.1,  # Recurrent dropout between LSTM layers
        )

        # 5. Attention: learned weights over BiLSTM outputs
        lstm_output_dim = lstm_hidden * 2  # Bidirectional
        self.attention = Attention(lstm_output_dim)

        # 6. Dense layers: classification head
        self.dense1 = nn.Linear(lstm_output_dim, dense_hidden)
        self.dropout = nn.Dropout(dropout_rate)
        self.dense2 = nn.Linear(dense_hidden, 1)

        # Initialize weights
        self._init_weights()

    def _init_weights(self):
        """Initialize weights with Xavier/Glorot uniform for stability."""
        for name, param in self.named_parameters():
            if not param.requires_grad:
                continue
            if param.dim() < 2:
                # 1D parameters (biases, batch norm, etc.)
                if 'dense2.bias' in name:
                    # Initialize final bias to -2.0 so sigmoid starts near 0.12
                    # This helps with class imbalance (mostly benign)
                    nn.init.constant_(param, -2.0)
                elif 'batch_norm' in name and 'weight' in name:
                    nn.init.ones_(param)
                elif 'batch_norm' in name and 'bias' in name:
                    nn.init.zeros_(param)
                else:
                    nn.init.zeros_(param)
            else:
                # 2D+ parameters (weights)
                if 'lstm' in name:
                    # LSTM: orthogonal initialization for recurrent weights
                    nn.init.orthogonal_(param)
                elif 'embedding' in name:
                    # Embedding: normal initialization
                    nn.init.normal_(param, mean=0.0, std=0.02)
                else:
                    # Conv and dense: Xavier uniform
                    nn.init.xavier_uniform_(param)

    def forward(self, input_ids: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            input_ids: [batch, max_seq_len] int32 tensor of character IDs
            
        Returns:
            threat_score: [batch, 1] float32 tensor of sigmoid scores
        """
        batch_size = input_ids.size(0)

        # 1. Embedding: [batch, seq_len] → [batch, seq_len, embedding_dim]
        embedded = self.embedding(input_ids)

        # 2. Conv1D branches: need [batch, embedding_dim, seq_len] for Conv1d
        embedded_t = embedded.permute(0, 2, 1)  # [batch, embedding_dim, seq_len]

        conv_outputs = []
        for conv in self.conv_branches:
            conv_out = F.relu(conv(embedded_t))  # [batch, conv_filters, seq_len]
            conv_outputs.append(conv_out)

        # Concatenate conv outputs: [batch, conv_filters * num_kernels, seq_len]
        conv_concat = torch.cat(conv_outputs, dim=1)

        # Batch normalization
        conv_concat = self.batch_norm(conv_concat)

        # Residual connection from embedding (projected to match conv dim)
        # This helps gradient flow for deeper training
        if hasattr(self, 'residual_proj'):
            residual = self.residual_proj(embedded_t)
            conv_concat = conv_concat + residual

        # Back to [batch, seq_len, conv_total]
        conv_concat = conv_concat.permute(0, 2, 1)

        # 3. BiLSTM: [batch, seq_len, conv_total] → [batch, seq_len, lstm_hidden*2]
        lstm_output, _ = self.lstm(conv_concat)

        # 4. Attention: [batch, seq_len, lstm_hidden*2] → [batch, lstm_hidden*2]
        context = self.attention(lstm_output)

        # 5. Dense classification head
        hidden = F.relu(self.dense1(context))
        hidden = self.dropout(hidden)
        threat_score = torch.sigmoid(self.dense2(hidden))

        return threat_score

    def count_parameters(self) -> int:
        """Count the total number of trainable parameters."""
        return sum(p.numel() for p in self.parameters() if p.requires_grad)

    def get_model_info(self) -> dict:
        """Return model architecture summary for documentation."""
        return {
            "architecture": "CharCNN-BiLSTM-Attention",
            "vocab_size": self.vocab_size,
            "embedding_dim": self.embedding_dim,
            "conv_filters": self.conv_filters,
            "conv_kernels": self.conv_kernels,
            "lstm_hidden": self.lstm_hidden,
            "lstm_output": self.lstm_hidden * 2,
            "dense_hidden": self.dense_hidden,
            "dropout_rate": self.dropout_rate,
            "max_seq_len": self.max_seq_len,
            "total_parameters": self.count_parameters(),
            "estimated_onnx_size_kb": int(self.count_parameters() * 4 / 1024),  # float32
        }


# =========================================================================
# Model Factory
# =========================================================================
def create_model(**kwargs) -> ThreatCNNBiLSTM:
    """Create a ThreatCNNBiLSTM model with default or custom parameters.
    
    Returns:
        ThreatCNNBiLSTM model instance
    """
    model = ThreatCNNBiLSTM(**kwargs)
    return model


if __name__ == "__main__":
    # Quick sanity check
    model = create_model()
    print(f"Model: {model.__class__.__name__}")
    print(f"Parameters: {model.count_parameters():,}")
    print(f"Info: {model.get_model_info()}")

    # Test forward pass
    dummy_input = torch.randint(0, VOCAB_SIZE, (4, MAX_SEQ_LEN), dtype=torch.int32)
    output = model(dummy_input)
    print(f"Input shape: {dummy_input.shape}")
    print(f"Output shape: {output.shape}")
    print(f"Output range: [{output.min().item():.4f}, {output.max().item():.4f}]")
    print("✅ Model forward pass OK")