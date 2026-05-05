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

const runQueryButton = document.getElementById("run-query");
const sqlQueryInput = document.getElementById("sql-query");
const queryMessage = document.getElementById("query-message");
const queryResultsTable = document.getElementById("query-results");

const generateChartButton = document.getElementById("generate-chart");
const chartFieldSelect = document.getElementById("chart-field");
const chartTypeSelect = document.getElementById("chart-type");

let logChart = null;

const getCsrfToken = () => window.csrfToken || "";

const showMessage = (container, message, type = "success") => {
    if (!container || container === document.body) {
        let alertHost = document.getElementById("global-alert-host");
        if (!alertHost) {
            alertHost = document.createElement("div");
            alertHost.id = "global-alert-host";
            alertHost.className = "container mt-3";
            document.body.prepend(alertHost);
        }
        alertHost.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
        return;
    }
    container.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
};

function numberToIndianWords(amount) {
    if (amount === null || amount === undefined || Number.isNaN(amount)) {
        return "Zero rupees";
    }

    const ones = ["", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine",
        "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen"];
    const tens = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"];

    const twoDigits = (num) => {
        if (num < 20) {
            return ones[num];
        }
        const remainder = num % 10;
        return `${tens[Math.floor(num / 10)]}${remainder ? ` ${ones[remainder]}` : ""}`.trim();
    };

    const threeDigits = (num) => {
        const hundred = Math.floor(num / 100);
        const remainder = num % 100;
        const hundredPart = hundred ? `${ones[hundred]} Hundred` : "";
        const remainderPart = remainder ? twoDigits(remainder) : "";
        return `${hundredPart}${hundredPart && remainderPart ? " " : ""}${remainderPart}`.trim();
    };

    const whole = Math.floor(Math.abs(amount));
    const paise = Math.round((Math.abs(amount) - whole) * 100);

    if (whole === 0) {
        return paise ? `${twoDigits(paise)} Paise` : "Zero Rupees";
    }

    const crore = Math.floor(whole / 10000000);
    const lakh = Math.floor((whole % 10000000) / 100000);
    const thousand = Math.floor((whole % 100000) / 1000);
    const remainder = whole % 1000;

    const parts = [];
    if (crore) parts.push(`${twoDigits(crore)} Crore`);
    if (lakh) parts.push(`${twoDigits(lakh)} Lakh`);
    if (thousand) parts.push(`${twoDigits(thousand)} Thousand`);
    if (remainder) parts.push(threeDigits(remainder));

    let words = `${parts.join(" ")} Rupees`;
    if (paise) {
        words += ` and ${twoDigits(paise)} Paise`;
    }
    return words.trim();
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
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": getCsrfToken(),
                },
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
    const isPieOrDoughnut = (chartType === 'pie' || chartType === 'doughnut');
    const isLine = (chartType === 'line');
    
    const colorPalette = [
        "#0d6efd",
        "#6610f2",
        "#198754",
        "#dc3545",
        "#ffc107",
        "#20c997",
        "#6f42c1",
        "#fd7e14",
        "#17a2b8",
        "#e83e8c",
        "#6c757d",
        "#343a40",
    ];

    // Truncate helper for long labels
    const truncate = (str, maxLen) => str.length > maxLen ? str.substring(0, maxLen) + '…' : str;

    const dataset = {
        label: "Count",
        data: dataPoints,
    };

    if (isLine) {
        dataset.borderColor = "#0d6efd";
        dataset.backgroundColor = "rgba(13, 110, 253, 0.15)";
        dataset.borderWidth = 3;
        dataset.fill = true;
        dataset.tension = 0.3;
        dataset.pointBackgroundColor = "#0d6efd";
        dataset.pointRadius = 5;
        dataset.pointHoverRadius = 7;
    } else {
        dataset.backgroundColor = colorPalette;
        dataset.borderWidth = 2;
        dataset.borderColor = isPieOrDoughnut ? '#fff' : colorPalette;
    }

    const total = dataPoints.reduce((a, b) => a + b, 0);

    const baseConfig = {
        type: chartType === "stackedBar" ? "bar" : chartType,
        data: {
            labels,
            datasets: [dataset],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            aspectRatio: isPieOrDoughnut ? 1.2 : 2,
            layout: {
                padding: {
                    bottom: 10
                }
            },
            plugins: {
                legend: {
                    display: isPieOrDoughnut,
                    position: "bottom",
                    labels: {
                        padding: 12,
                        boxWidth: 14,
                        font: {
                            size: 12
                        },
                        generateLabels: function(chart) {
                            const data = chart.data;
                            if (data.labels.length && data.datasets.length) {
                                return data.labels.map((label, i) => {
                                    const value = data.datasets[0].data[i];
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return {
                                        text: `${truncate(label, 25)}: ${value} (${percentage}%)`,
                                        fillStyle: data.datasets[0].backgroundColor[i % colorPalette.length],
                                        strokeStyle: '#fff',
                                        lineWidth: 1,
                                        hidden: false,
                                        index: i
                                    };
                                });
                            }
                            return [];
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        title: function(items) {
                            // Show full label name (untruncated) in tooltip title
                            if (items.length > 0) {
                                const idx = items[0].dataIndex;
                                return items[0].chart.data.labels[idx];
                            }
                            return '';
                        },
                        label: function(context) {
                            const value = context.parsed.y !== undefined ? context.parsed.y : context.parsed;
                            const percentage = ((value / total) * 100).toFixed(1);
                            return ` Count: ${value}  (${percentage}%)`;
                        }
                    }
                }
            },
        },
    };

    // Scales for bar and line charts
    if (chartType === "stackedBar") {
        baseConfig.options.scales = {
            x: { stacked: true, ticks: { maxRotation: 45, minRotation: 0, autoSkip: false, font: { size: 11 } } },
            y: { stacked: true, beginAtZero: true },
        };
    } else if (!isPieOrDoughnut) {
        baseConfig.options.scales = {
            x: {
                ticks: {
                    maxRotation: 45,
                    minRotation: 0,
                    autoSkip: false,
                    font: { size: 11 },
                    callback: function(value) {
                        const label = this.getLabelForValue(value);
                        return truncate(label, 20);
                    }
                }
            },
            y: { 
                beginAtZero: true,
                ticks: { font: { size: 12 } }
            }
        };
    }

    return baseConfig;
};

if (generateChartButton) {
    generateChartButton.addEventListener("click", async () => {
        const field = chartFieldSelect.value;
        const chartType = chartTypeSelect.value;

        // Toggle container width based on chart type
        const chartContainer = document.querySelector('.chart-container');
        if (chartContainer) {
            if (chartType === 'pie' || chartType === 'doughnut') {
                chartContainer.classList.remove('chart-wide');
            } else {
                chartContainer.classList.add('chart-wide');
            }
        }

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
