while IFS= read -r word; do
  len=$(( ${#word} + 3 ))
  crunch "$len" "$len" -t "${word}%%^" -o "out_${word}.txt"
done < keyword.txt

cat out_*.txt > output.txt
