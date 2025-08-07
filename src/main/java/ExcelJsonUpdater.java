import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.*;

public class ExcelJsonUpdater {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java -jar ExcelJsonUpdater.jar <input.xlsx> <input.json>");
            return;
        }

        String excelFilePath = args[0];
        String jsonFilePath = args[1];

        try (InputStream excelInputStream = new FileInputStream(excelFilePath);
             Workbook workbook = new XSSFWorkbook(excelInputStream)) {

            Sheet sheet = workbook.getSheetAt(0);
            Set<String> existingCveIds = new HashSet<>();

            for (Row row : sheet) {
                for (Cell cell : row) {
                    if (cell.getCellType() == CellType.STRING && cell.getStringCellValue().startsWith("CVE-")) {
                        existingCveIds.add(cell.getStringCellValue().trim());
                    }
                }
            }

            // Buat cell style kuning untuk highlight
            CellStyle yellowStyle = workbook.createCellStyle();
            yellowStyle.setFillForegroundColor(IndexedColors.YELLOW.getIndex());
            yellowStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);

            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(new File(jsonFilePath));
            JsonNode results = root.get("results");

            // Kumpulkan semua cveId dari JSON
            Set<String> jsonCveIds = new HashSet<>();
            for (JsonNode result : results) {
                JsonNode vulns = result.get("vulnerabilities");
                if (vulns == null || !vulns.isArray()) continue;
                for (JsonNode vuln : vulns) {
                    String cveId = vuln.has("id") ? vuln.get("id").asText() : null;
                    if (cveId != null) jsonCveIds.add(cveId);
                }
            }

            // Cari baris di Excel yang cveId-nya tidak ada di jsonCveIds
            List<Integer> rowsToDelete = new ArrayList<>();
            for (int i = 0; i <= sheet.getLastRowNum(); i++) {
                Row row = sheet.getRow(i);
                if (row == null) continue;
                String foundCveId = null;
                for (Cell cell : row) {
                    if (cell.getCellType() == CellType.STRING && cell.getStringCellValue().startsWith("CVE-")) {
                        foundCveId = cell.getStringCellValue().trim();
                        break;
                    }
                }
                if (foundCveId != null && !jsonCveIds.contains(foundCveId)) {
                    rowsToDelete.add(i);
                }
            }

            // Hapus baris dari bawah ke atas
            for (int i = rowsToDelete.size() - 1; i >= 0; i--) {
                int rowIndex = rowsToDelete.get(i);
                sheet.removeRow(sheet.getRow(rowIndex));
                // Optional: shift rows up agar rapat
                if (rowIndex < sheet.getLastRowNum()) {
                    sheet.shiftRows(rowIndex + 1, sheet.getLastRowNum(), -1);
                }
            }

            if (results == null || !results.isArray()) {
                System.out.println("No 'results' array found in JSON.");
                return;
            }

            int newEntries = 0;
            for (JsonNode result : results) {
                JsonNode vulns = result.get("vulnerabilities");
                if (vulns == null || !vulns.isArray()) continue;

                for (JsonNode vuln : vulns) {
                    String cveId = vuln.has("id") ? vuln.get("id").asText() : null;
                    String severity = vuln.has("severity") ? vuln.get("severity").asText() : "";
                    String packagePath = vuln.has("packagePath") ? vuln.get("packagePath").asText() : null;
                    String discoveryDateRaw = vuln.has("discoveryDate") ? vuln.get("discoveryDate").asText() : "";
                    String discoveryDateFormatted = "";
                    if (!discoveryDateRaw.isEmpty()) {
                        try {
                            SimpleDateFormat inputFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
                            Date date = inputFormat.parse(discoveryDateRaw);
                            SimpleDateFormat outputFormat = new SimpleDateFormat("dd MMM yyyy", Locale.ENGLISH);
                            discoveryDateFormatted = outputFormat.format(date);
                        } catch (Exception e) {
                            // ignore format errors, leave date blank
                        }
                    }

                    // Cek duplikasi sebelum insert
                    if (cveId == null || !cveId.startsWith("CVE-") || existingCveIds.contains(cveId)) {
                        continue;
                    }
                    existingCveIds.add(cveId);

                    Row newRow = sheet.createRow(sheet.getLastRowNum() + 1);
                    // Data dimulai dari kolom ke-3 (indeks 2: id, 3: severity, 4: packagePath, 5: discoveryDate)
                    Cell cell0 = newRow.createCell(2); // id
                    cell0.setCellValue(cveId);
                    cell0.setCellStyle(yellowStyle);

                    Cell cellSeverity = newRow.createCell(3); // severity
                    cellSeverity.setCellValue(severity);

                    Cell cell1 = newRow.createCell(4); // packagePath
                    cell1.setCellValue(packagePath);

                    Cell cell2 = newRow.createCell(8); // discoveryDate
                    cell2.setCellValue(discoveryDateFormatted);

                    newEntries++;
                }
            }

            try (OutputStream out = new FileOutputStream("output.xlsx")) {
                workbook.write(out);
            }

            System.out.println("Done. Added " + newEntries + " new CVE(s) to output.xlsx");

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("An error occurred while processing the files.");
        }
    }
}
