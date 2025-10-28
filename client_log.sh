#!/bin/bash
RESOLVER_IP="10.0.0.5"
DOMAINS_FILE="urls_h2.txt"
LOG_FILE="client_log.csv"

# Create header if log file does not exist
if [ ! -f "$LOG_FILE" ]; then
    echo "Timestamp,Domain,Resolver,QueryTime(ms),Status,Answer" > "$LOG_FILE"
fi

# Check if domain list file exists
if [ ! -f "$DOMAINS_FILE" ]; then
    echo "Error: $DOMAINS_FILE not found!"
    exit 1
fi

# Loop over domains
while read -r DOMAIN; do
    if [ -z "$DOMAIN" ]; then
        continue
    fi
    echo "Querying $DOMAIN via $RESOLVER_IP ..."
    START=$(date +%s%3N)  # current time in milliseconds
    DIG_OUTPUT=$(dig @$RESOLVER_IP "$DOMAIN" +stats +noall +answer +recurse)
    STATUS=$?
    END=$(date +%s%3N)
    TOTAL_TIME=$((END - START))

    if [ $STATUS -ne 0 ]; then
        ANSWER="No response"
        STATUS_TEXT="FAIL"
    else
        # Extract final status and first answer (if any)
        ANSWER_LINE=$(echo "$DIG_OUTPUT" | head -n 1)
        if [ -z "$ANSWER_LINE" ]; then
            STATUS_TEXT="NO_ANSWER"
            ANSWER="(none)"
        else
            STATUS_TEXT="OK"
            ANSWER=$(echo "$ANSWER_LINE" | awk '{print $5}')
        fi
    fi
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$TIMESTAMP,$DOMAIN,$RESOLVER_IP,$TOTAL_TIME,$STATUS_TEXT,$ANSWER" >> "$LOG_FILE"
done < "$DOMAINS_FILE"
