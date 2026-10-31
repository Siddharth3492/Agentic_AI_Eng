# Agentic-AI-Engineering
 
# 🎓 Intelligent Student Support Agent

> **Agentic AI Engineering — Assignments 1 & 2**  
> An offline-first, ReAct-style agentic AI system that assists students with academic queries, policy lookups, support tickets, and course-change workflows — with role-based access control, persistent memory, human-in-the-loop approvals, and a full audit trail.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture & Design](#architecture--design)
- [Tech Stack](#tech-stack)
- [Demo Credentials](#demo-credentials)
- [Getting Started](#getting-started)
- [Agent Tools & Intent Routing](#agent-tools--intent-routing)
- [Security, Privacy & Safety Controls](#security-privacy--safety-controls)
- [Automated Evaluation Suite](#automated-evaluation-suite)
- [Project Structure](#project-structure)
- [Assignment Criteria Coverage](#assignment-criteria-coverage)

---

## Overview

The **Intelligent Student Support Agent** is a standalone conversational AI portal built using **Streamlit** and **SQLite**. It demonstrates a bounded, robust **ReAct-style agent loop** featuring a deterministic planner, validated tool dispatcher, in-tool authorization enforcement, persistent preference memory, and a tamper-evident audit log. 

The application works completely offline using built-in deterministic planning, while offering an optional LLM tool-calling fallback via Groq.

---

## Key Features

### 👨‍🎓 Student Capabilities
- **💰 Fee Status:** Access own pending and paid fee details securely.
- **🏅 Scholarship Status:** Check verified scholarship eligibility and disbursement states.
- **📜 Policy Retrieval:** Inquire about student handbook policies (payment issues, late fees, course changes) backed by selective chunk retrieval.
- **🎫 Support Requests:** Generate idempotent support tickets with unique tracking codes.
- **🔄 Course-Change Requests:** Submit requests to switch courses (queued for administrative review).
- **💾 Safe Memory Management:** Persist user-specific non-sensitive preferences (e.g., preferred name, communication channel).

### 🛡️ Administrator Capabilities
- **⏳ Approval Desk:** Review, approve, or reject student course-change requests in real-time.
- **📋 Human-Readable Audit Log:** Monitor detailed system events with visual decision statuses (`Allowed` / `Denied`) and formatted timestamps.
- **🧪 Automated Evaluation Suite:** One-click execution of 16 comprehensive verification checks against an isolated database.

---

## Architecture & Design

```
User Input
    │
    ▼
┌─────────────────────────────┐
│   Sensitive-Content Filter  │  ◄── Blocks passwords, OTPs, PINs, passcodes
└────────────┬────────────────┘
             │
    ▼
┌─────────────────────────────┐
│   Deterministic Planner     │  ◄── Rule-based intent routing with priority:
│   (+ optional Groq LLM)     │      Memory > Policy > Fees > Scholarship
└────────────┬────────────────┘      > Course-Change > Support Tickets
             │
    ▼
┌─────────────────────────────┐
│   Tool Dispatcher           │  ◄── Validates tool names & schemas
└────────────┬────────────────┘
             │
    ▼
┌─────────────────────────────┐
│   Authorization Layer       │  ◄── Enforces role & ID access at the tool level
│   (in-tool checks)          │
└────────────┬────────────────┘
             │
    ▼
┌─────────────────────────────┐
│   SQLite Database           │  ◄── Tables: users, students, memories,
│                             │      tickets, change_requests, audit_log, traces
└────────────┬────────────────┘
             │
    ▼
┌─────────────────────────────┐
│   Formatted UI Output       │  ◄── Actionable response with trace & latency metadata
└─────────────────────────────┘
```

---

## Tech Stack

| Component | Technology |
|---|---|
| **Frontend UI** | Streamlit (Custom CSS, dark sidebar, responsive cards, Inter font) |
| **Agent Logic** | Python (Manual ReAct loop, bounded turns, regex-based deterministic planner) |
| **Data Storage** | SQLite (`sqlite3` with foreign keys enabled, PBKDF2 password hashing) |
| **Optional LLM** | Groq API (`llama-3.3-70b-versatile` function calling) |
| **Language** | Python 3.10+ |

---

## Demo Credentials

The database initializes automatically with test demonstration accounts:

| User ID | Full Name | Role | Password |
|---|---|---|---|
| `STU1001` | Arjun Mehta | Student | `demo123` |
| `STU1002` | Riya Shah | Student | `demo123` |
| `STU1003` | Kabir Patel | Student | `demo123` |
| `ADMIN01` | Programme Administrator | Admin | `admin123` |

> ⚠️ *These credentials and records are for academic evaluation purposes only.*

---

## Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
```

### 2. Install Dependencies
```bash
pip install streamlit pandas python-dotenv
# Optional: only if using Groq LLM integration
pip install groq
```

### 3. (Optional) Configure Environment Variables
Create a `.env` file in the root directory if you want to enable Groq tool-calling:
```env
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile
```
*(If omitted, the agent seamlessly operates in offline deterministic mode).*

### 4. Run the Streamlit Application
```bash
streamlit run Intelligent_Student_Support_Agent.py
```
Open **[http://localhost:8501](http://localhost:8501)** in your web browser.

---

## Agent Tools & Intent Routing

The agent exposes 8 manual tools registered with standard function schemas:

| Tool Name | Access Scope | Description |
|---|---|---|
| `get_fee_status` | Student (own) | Retrieves current fee balance and payment status |
| `get_scholarship_status` | Student (own) | Retrieves scholarship evaluation and disbursement details |
| `get_student_record` | Student (own) | Fetches complete student academic profile |
| `search_policy` | All Users | Performs selective keyword retrieval on policy handbook chunks |
| `get_memory` | Student (own) | Reads non-sensitive saved preferences |
| `save_memory` | Student (own) | Stores whitelisted user preferences (`preferred_name`, `programme`, `communication_preference`) |
| `create_support_request` | Student (own) | Creates idempotent support ticket (`TKT-XXXX`) |
| `request_course_change` | Student (own) | Submits course-change request (`CR-XXXX`) with `Pending approval` status |

### Priority-Based Routing Logic
To avoid ambiguous keyword collisions (e.g., distinguishing "fee policy" from "fee status"):
1. **Memory Write:** Explicit save commands (`"Remember my preferred name is..."`)
2. **Memory Read:** Preference lookups (`"What do you remember?"`)
3. **Policy Retrieval:** Policy, rules, deadlines, payment portal failures (`"What does policy say about late fee payment?"`)
4. **Fee Status:** Direct personal balance inquiries (`"What is my fee status?"`)
5. **Scholarship:** Personal scholarship inquiries (`"What is my scholarship status?"`)
6. **Course Change:** Transfer / switch course requests (`"Change my course to Data Science"`)
7. **Support Request:** Tickets and helpdesk requests (`"Raise a support ticket"`)

---

## Security, Privacy & Safety Controls

- **Zero Cross-Student Leakage:** Student IDs are verified in each tool against the signed-in session; accessing another student's ID triggers an immediate denial and audit log entry.
- **Sensitive Data Interception:** Input containing OTPs, passwords, PINs, or raw numeric secrets is blocked before tool dispatch and never persisted.
- **Safe Preference Whitelisting:** Arbitrary memory storage is rejected; only validated keys (`preferred_name`, `communication_preference`, `programme`) are accepted.
- **Human-In-The-Loop (HITL) Gate:** Course changes cannot be executed by the agent alone. They remain in `Pending approval` until an authorized administrator explicitly approves the change.
- **Auditability:** Every tool invocation and administrative decision is logged into an immutable `audit_log` table with timestamps, actor IDs, decision status (`ALLOWED` / `DENIED`), and details.

---

## Automated Evaluation Suite

The application includes an internal test suite accessible via the Administrator Dashboard (`ADMIN01`):

1. Sign in as `ADMIN01` (`admin123`).
2. Navigate to the **Assignment Evaluation** section.
3. Click **"▶ Run 16 Assignment Checks"**.

### Test Matrix
- **Authentication:** Student & Admin sign-in verification
- **Data Access:** Own fee & scholarship retrieval
- **Policy Search:** Selective handbook chunk retrieval & no fabricated promises
- **Memory Safety:** Whitelist persistence & credential rejection
- **Support Tickets:** Idempotent ticket creation
- **Agent Decisioning:** Accurate tool selection & ReAct formatting
- **Security Boundaries:** Input sanitization & cross-student access blocking
- **HITL Workflow:** Course change rejection (unchanged state) vs. approval (state updated)
- **Audit Logging:** Verification of allowed and denied audit records

---

## Project Structure

```
├── Intelligent_Student_Support_Agent.py   # Core single-file application (UI, Agent & DB logic)
├── student_support.db                     # SQLite database (auto-generated on startup)
├── README.md                              # Project documentation
└── .env                                   # (Optional) Environment variables
```

---

## Assignment Criteria Coverage

| Evaluation Criteria | Implementation Detail | Status |
|---|---|:---:|
| **ReAct Agent Loop** | Bounded turn execution (max 3 turns), tool request & observation logging | ✅ |
| **Tool Registry** | 8 validated tools with structured schema definitions | ✅ |
| **Policy Retrieval** | Chunked text retrieval with evidence citations; prevents hallucinated policies | ✅ |
| **State & Memory** | SQLite persistence with strict regex whitelisting for safe preferences | ✅ |
| **Security & Privacy** | In-tool role/identity validation, cross-student blocking, secret filtering | ✅ |
| **Administrative Control** | Approval desk for state-modifying actions (course change) | ✅ |
| **Audit & Tracing** | Timestamped audit entries, run IDs, tool latency, and token telemetry | ✅ |
| **Evaluation Suite** | 16/16 automated test checks passing on isolated test database | ✅ |
| **Modern Responsive UI** | Custom styled Streamlit interface with clear visual hierarchy | ✅ |

---

## Author
Siddharth Hakani

**Siddharth**  
*Agentic AI Engineering — Assignments 1 & 2*
