let generatedEmailB64 = null;
let generatedEmailText = null;
let latestReport = null;

function showSection(sectionId) {
    document.querySelectorAll(".page-section").forEach(section => {
        section.classList.remove("active");
    });

    document.querySelectorAll(".nav-item").forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.section === sectionId
        );
    });

    document.getElementById(sectionId).classList.add("active");

    const names = {
        dashboard: "Dashboard",
        analyzer: "Email Analyzer",
        spf: "SPF Checker",
        dkim: "DKIM Verifier",
        dmarc: "DMARC Analyzer",
        reports: "Security Reports"
    };

    document.getElementById("page-name").textContent =
        names[sectionId] || "Dashboard";

    window.scrollTo({ top: 0, behavior: "smooth" });
}

document.querySelectorAll(".nav-item").forEach(button => {
    button.addEventListener("click", () => {
        showSection(button.dataset.section);
    });
});

function showToast(message) {
    const toast = document.getElementById("toast");
    toast.textContent = message;
    toast.classList.add("show");

    setTimeout(() => {
        toast.classList.remove("show");
    }, 3000);
}

async function generateDemo() {
    try {
        showToast("Generating signed demo email...");

        const response = await fetch("/api/demo-email", {
            method: "POST"
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Demo generation failed.");
        }

        generatedEmailB64 = data.email_b64;
        generatedEmailText = data.email;

        document.getElementById("email-input").value = data.email;

        showSection("analyzer");
        showToast("Signed demo email generated successfully.");

    } catch (error) {
        showToast(error.message);
    }
}

function clearEmail() {
    document.getElementById("email-input").value = "";

    generatedEmailB64 = null;
    generatedEmailText = null;

    document.getElementById("results-area").classList.add("hidden");

    showToast("Email input cleared.");
}

function setStatus(elementId, value) {
    const element = document.getElementById(elementId);

    element.textContent = value || "UNKNOWN";

    element.className = "";

    if (value === "PASS") {
        element.classList.add("pass");
    } else if (value === "FAIL" || value === "INVALID_RECORD") {
        element.classList.add("fail");
    } else {
        element.classList.add("neutral");
    }
}

function addDetail(container, label, value) {
    const row = document.createElement("div");
    row.className = "detail-row";

    const left = document.createElement("span");
    left.textContent = label;

    const right = document.createElement("b");
    right.textContent = value ?? "Not available";

    row.append(left, right);
    container.appendChild(row);
}

async function analyzeEmail() {
    const email = document.getElementById("email-input").value.trim();

    if (!email) {
        showToast("Please enter an email first.");
        return;
    }

    const button = document.querySelector(".analyze-btn");
    button.disabled = true;
    button.textContent = "Analyzing email...";

    try {
        const payload = {
            email: email,
            client_ip: document.getElementById("client-ip").value.trim(),
            mail_from_domain: document.getElementById("mail-domain").value.trim(),
            spf_record: document.getElementById("spf-record").value.trim(),
            dmarc_record: document.getElementById("dmarc-record").value.trim()
        };

        if (generatedEmailB64 && email === generatedEmailText) {
            payload.email_b64 = generatedEmailB64;
            payload.email = "";
        }

        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Email analysis failed.");
        }

        latestReport = data.results;

        displayResults(latestReport);

        showToast("Email analysis completed.");

    } catch (error) {
        showToast(error.message);

    } finally {
        button.disabled = false;
        button.innerHTML = 'Analyze Email <span>?</span>';
    }
}

function displayResults(report) {
    const independent = report.independent_results;
    const dmarc = independent.dmarc;

    setStatus("spf-result", independent.spf);
    setStatus("dkim-result", independent.dkim);
    setStatus("dmarc-result", dmarc.result);

    const details = document.getElementById("detail-content");
    details.replaceChildren();

    addDetail(details, "Sender", report.email.from);
    addDetail(details, "Recipient", report.email.to);
    addDetail(details, "Subject", report.email.subject);

    addDetail(details, "SPF result", independent.spf);
    addDetail(details, "DKIM result", independent.dkim);
    addDetail(details, "DMARC policy", dmarc.policy);

    addDetail(details, "SPF alignment", String(dmarc.spf_aligned ?? "N/A"));
    addDetail(details, "DKIM alignment", String(dmarc.dkim_aligned ?? "N/A"));
    addDetail(details, "DMARC explanation", dmarc.reason);

    const reported = report.reported_results;

    addDetail(details, "Reported SPF", reported.spf);
    addDetail(details, "Reported DKIM", reported.dkim);
    addDetail(details, "Reported DMARC", reported.dmarc);

    document.getElementById("results-area").classList.remove("hidden");

    document.getElementById("report-status").textContent =
        "Latest analysis completed. Your JSON report is ready to download.";

    document.getElementById("results-area").scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}

function downloadReport() {
    if (!latestReport) {
        showToast("Run an analysis before downloading a report.");
        return;
    }

    const report = {
        project: "Secure Email Authentication Gateway",
        generated_at: new Date().toISOString(),
        results: latestReport
    };

    const blob = new Blob(
        [JSON.stringify(report, null, 4)],
        { type: "application/json" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "secure_email_authentication_report.json";

    link.click();

    URL.revokeObjectURL(url);

    showToast("Security report downloaded.");
}
