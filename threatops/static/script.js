// Format number with Indian notation - simplified
function formatIndianNumber(num, addRupeeSymbol = true) {
    if (num === null || num === undefined || isNaN(num)) return addRupeeSymbol ? '₹0.00' : '0';
    
    const absNum = Math.abs(num);
    let formatted;
    
    if (absNum >= 10000000) {
        formatted = (absNum / 10000000).toFixed(2) + ' Cr';
    } else if (absNum >= 100000) {
        formatted = (absNum / 100000).toFixed(2) + ' L';
    } else if (absNum >= 1000) {
        formatted = (absNum / 1000).toFixed(2) + 'K';
    } else {
        formatted = absNum.toFixed(2);
    }
    
    const prefix = addRupeeSymbol ? '₹' : '';
    return num < 0 ? `-${prefix}${formatted}` : `${prefix}${formatted}`;
}

const loadSampleButton = document.getElementById("load-sample");
const loadSampleForm = document.getElementById("load-sample-form");
const loadSampleMessage = document.getElementById("load-sample-message");
const dashboardMessage = document.getElementById("dashboard-message");

const runQueryButton = document.getElementById("run-query");
const sqlQueryInput = document.getElementById("sql-query");
const queryMessage = document.getElementById("query-message");
const queryResultsTable = document.getElementById("query-results");

const generateChartButton = document.getElementById("generate-chart");
const chartFieldSelect = document.getElementById("chart-field");
const chartTypeSelect = document.getElementById("chart-type");

let logChart = null;

const showMessage = (container, message, type = "success") => {
    if (!container) {
        return;
    }
    container.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
};

const loadSampleDataset = async (messageContainer) => {
    try {
        const response = await fetch("/load_sample_dataset", { method: "POST" });
        const data = await response.json();
        if (!response.ok) {
            showMessage(messageContainer, data.message || "Failed to load sample data.", "danger");
            return;
        }
        showMessage(messageContainer, data.message, "success");
    } catch (error) {
        showMessage(messageContainer, `Request failed: ${error}`, "danger");
    }
};

if (loadSampleButton) {
    loadSampleButton.addEventListener("click", () => loadSampleDataset(loadSampleMessage));
}

if (loadSampleForm) {
    loadSampleForm.addEventListener("submit", (event) => {
        event.preventDefault();
        loadSampleDataset(dashboardMessage);
    });
}

if (runQueryButton) {
    runQueryButton.addEventListener("click", async () => {
        const query = sqlQueryInput.value.trim();
        if (!query) {
            showMessage(queryMessage, "Please enter a SQL query.", "danger");
            return;
        }
        try {
            const response = await fetch("/run_query", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ query }),
            });
            const data = await response.json();
            if (!response.ok) {
                showMessage(queryMessage, data.error || "Query failed.", "danger");
                return;
            }
            showMessage(queryMessage, "Query executed successfully.", "success");
            renderQueryResults(data.columns, data.rows);
        } catch (error) {
            showMessage(queryMessage, `Request failed: ${error}`, "danger");
        }
    });
}

const renderQueryResults = (columns, rows) => {
    if (!queryResultsTable) {
        return;
    }

    const thead = queryResultsTable.querySelector("thead");
    const tbody = queryResultsTable.querySelector("tbody");

    thead.innerHTML = "";
    tbody.innerHTML = "";

    const headerRow = document.createElement("tr");
    columns.forEach((column) => {
        const th = document.createElement("th");
        th.textContent = column;
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);

    rows.forEach((row) => {
        const tr = document.createElement("tr");
        columns.forEach((column) => {
            const td = document.createElement("td");
            const value = row[column];
            
            // Check if column name suggests it's a currency value
            const currencyColumns = ['implementation_cost', 'total_cost', 'cost', 'amount', 'price'];
            const isCurrency = currencyColumns.some(col => column.toLowerCase().includes(col));
            
            // Format numeric values
            if (isCurrency && value !== null && !isNaN(value)) {
                td.textContent = formatIndianNumber(parseFloat(value));
            } else if (!isCurrency && typeof value === 'number') {
                td.textContent = formatIndianNumber(value, false);
            } else {
                td.textContent = value;
            }
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
};

const buildChartConfig = (chartType, labels, dataPoints) => {
    const baseConfig = {
        type: chartType === "stackedBar" ? "bar" : chartType,
        data: {
            labels,
            datasets: [
                {
                    label: "Log Count",
                    data: dataPoints,
                    backgroundColor: [
                        "#0d6efd",
                        "#6610f2",
                        "#198754",
                        "#dc3545",
                        "#ffc107",
                        "#20c997",
                        "#6f42c1",
                    ],
                },
            ],
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: "bottom",
                },
            },
        },
    };

    if (chartType === "stackedBar") {
        baseConfig.options.scales = {
            x: { stacked: true },
            y: { stacked: true, beginAtZero: true },
        };
    }

    return baseConfig;
};

if (generateChartButton) {
    generateChartButton.addEventListener("click", async () => {
        const field = chartFieldSelect.value;
        const chartType = chartTypeSelect.value;

        try {
            const response = await fetch(`/chart_data?field=${field}`);
            const data = await response.json();
            if (!response.ok) {
                showMessage(document.body, data.error || "Chart data failed.", "danger");
                return;
            }
            if (logChart) {
                logChart.destroy();
            }
            const ctx = document.getElementById("log-chart");
            logChart = new Chart(ctx, buildChartConfig(chartType, data.labels, data.counts));
        } catch (error) {
            showMessage(document.body, `Chart request failed: ${error}`, "danger");
        }
    });
}
