awk 'BEGIN { FS="[:,]"; OFS="," }
{
    for (i = 1; i <= NF; i += 2) {
        gsub(/ /, "", $i); # Remove spaces from keys
        header = (header ? header OFS : "") $i;
        value = (value ? value OFS : "") $(i+1);
    }
    print header > "reports/mi.csv";
    print value >> "reports/mi.csv";
}' reports/trivy-results.json