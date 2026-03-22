package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;
    private volatile Program lastKnownProgram;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, renameDataAtAddress(params.get("address"), params.get("newName")));
        });

        server.createContext("/get_symbol_at", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getSymbolAt(address));
        });

        server.createContext("/symbol_at", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getSymbolAt(address));
        });

        server.createContext("/getSymbolAt", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getSymbolAt(address));
        });

        server.createContext("/symbolAt", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getSymbolAt(address));
        });

        server.createContext("/get_symbol", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getSymbolAt(address));
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/create_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String entry = params.get("entry");
            String name = params.get("name");
            String bodyStart = params.get("body_start");
            String bodyEnd = params.get("body_end");
            String comment = params.get("comment");
            sendResponse(exchange, createFunctionByAddress(entry, name, bodyStart, bodyEnd, comment));
        });

        server.createContext("/delete_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String entry = params.get("entry");
            sendResponse(exchange, deleteFunctionByAddress(entry));
        });

        server.createContext("/get_function_containing", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionContaining(address));
        });

        server.createContext("/read_region", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String start = qparams.get("start");
            String end = qparams.get("end");
            sendResponse(exchange, readRegion(start, end));
        });

        server.createContext("/disassemble_region", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String start = qparams.get("start");
            String end = qparams.get("end");
            sendResponse(exchange, disassembleRegion(start, end));
        });

        server.createContext("/get_instruction_window", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int beforeCount = parseIntOrDefault(qparams.get("before_count"), 5);
            int afterCount = parseIntOrDefault(qparams.get("after_count"), 5);
            sendResponse(exchange, getInstructionWindow(address, beforeCount, afterCount));
        });

        server.createContext("/search_instructions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String query = qparams.get("query");
            String mode = qparams.get("mode");
            int limit = parseIntOrDefault(qparams.get("limit"), 200);
            sendResponse(exchange, searchInstructions(query, mode, limit));
        });

        server.createContext("/get_data_uses", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            boolean includeOperandScans = parseBooleanOrDefault(qparams.get("include_operand_scans"), true);
            int limit = parseIntOrDefault(qparams.get("limit"), 200);
            sendResponse(exchange, getDataUses(address, includeOperandScans, limit));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            String status = success ? "ok" : "failed";
            sendResponse(exchange,
                status + ": set_decompiler_comment address=" + safeValueForResponse(address) +
                " comment=\"" + previewForResponse(comment) + "\"");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            String status = success ? "ok" : "failed";
            sendResponse(exchange,
                status + ": set_disassembly_comment address=" + safeValueForResponse(address) +
                " comment=\"" + previewForResponse(comment) + "\"");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            String status = success ? "ok" : "failed";
            sendResponse(exchange,
                status + ": rename_function_by_address function_address=" + safeValueForResponse(functionAddress) +
                " new_name=" + safeValueForResponse(newName));
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);
            String status = result.isSuccess() ? "ok" : "failed";
            String base = status + ": set_function_prototype function_address=" +
                safeValueForResponse(functionAddress) + " prototype=\"" +
                previewForResponse(prototype) + "\"";

            if (result.getErrorMessage().isBlank()) {
                sendResponse(exchange, base);
            } else {
                sendResponse(exchange, base + "\n" + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        // Alias route for clients that use get_* naming for xref tools.
        server.createContext("/get_xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        // Alias route for clients that use get_* naming for xref tools.
        server.createContext("/get_xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        server.createContext("/set_comments", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String batch = params.get("batch");
            sendResponse(exchange, setCommentsBatch(batch, CodeUnit.EOL_COMMENT, "Set disassembly comments batch"));
        });

        server.createContext("/set_decompiler_comments", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String batch = params.get("batch");
            sendResponse(exchange, setCommentsBatch(batch, CodeUnit.PRE_COMMENT, "Set decompiler comments batch"));
        });

        server.createContext("/rename_functions_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String batch = params.get("batch");
            sendResponse(exchange, renameFunctionsByAddressBatch(batch));
        });

        server.createContext("/apply_program_edit_plan", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String plan = params.get("plan");
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            sendResponse(exchange, applyProgramEditPlan(plan, dryRun));
        });

        server.createContext("/reanalyze_region", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String start = params.get("start");
            String end = params.get("end");
            sendResponse(exchange, reanalyzeRegion(start, end));
        });

        server.createContext("/patch_bytes_and_reanalyze", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String start = params.get("start");
            String bytes = params.get("bytes");
            String comment = params.get("comment");
            sendResponse(exchange, patchBytesAndReanalyze(start, bytes, comment));
        });

        server.createContext("/analyze_function_boundaries", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String start = qparams.get("start");
            String end = qparams.get("end");
            sendResponse(exchange, analyzeFunctionBoundaries(start, end));
        });

        server.createContext("/get_project_access_info", exchange -> {
            sendResponse(exchange, getProjectAccessInfo());
        });

        server.createContext("/open_current_program_readonly", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            int version = parseIntOrDefault(params.get("version"), -1);
            boolean makeCurrent = parseBooleanOrDefault(params.get("make_current"), true);
            sendResponse(exchange, openCurrentProgramReadonly(version, makeCurrent));
        });

        server.createContext("/run_readonly_script", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String scriptPath = params.get("script_path");
            String scriptText = params.get("script_text");
            sendResponse(exchange, runReadonlyScript(scriptPath, scriptText));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private String renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return "failed: rename_data no program loaded";
        if (addressStr == null || addressStr.isBlank()) return "failed: rename_data address is required";
        if (newName == null || newName.isBlank()) return "failed: rename_data new_name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        AtomicReference<String> result = new AtomicReference<>("failed: rename_data unknown error");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.set("failed: rename_data invalid address=" + safeValueForResponse(addressStr));
                        return;
                    }

                    SymbolTable symTable = program.getSymbolTable();
                    Symbol symbol = symTable.getPrimarySymbol(addr);
                    String previousName = symbol != null ? symbol.getName() : "";

                    if (symbol != null) {
                        symbol.setName(newName, SourceType.USER_DEFINED);
                    } else {
                        symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                    }

                    Symbol resolved = symTable.getPrimarySymbol(addr);
                    boolean hasDefinedData = program.getListing().getDefinedDataAt(addr) != null;
                    if (resolved != null && newName.equals(resolved.getName())) {
                        success.set(true);
                        result.set(
                            "ok: rename_data address=" + safeValueForResponse(addr.toString()) +
                            " new_name=" + safeValueForResponse(newName) +
                            " resolved_symbol=" + safeValueForResponse(resolved.getName()) +
                            " source=" + safeValueForResponse(resolved.getSource().toString()) +
                            " symbol_type=" + safeValueForResponse(resolved.getSymbolType().toString()) +
                            " defined_data=" + hasDefinedData +
                            (previousName.isBlank() || previousName.equals(newName)
                                ? ""
                                : " previous_name=" + safeValueForResponse(previousName))
                        );
                    } else {
                        result.set(
                            "failed: rename_data address=" + safeValueForResponse(addr.toString()) +
                            " requested_name=" + safeValueForResponse(newName) +
                            " resolved_symbol=" + safeValueForResponse(resolved != null ? resolved.getName() : "<none>") +
                            " defined_data=" + hasDefinedData
                        );
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                    result.set(
                        "failed: rename_data address=" + safeValueForResponse(addressStr) +
                        " new_name=" + safeValueForResponse(newName) +
                        " error=" + safeValueForResponse(e.getMessage())
                    );
                }
                finally {
                    boolean committed = program.endTransaction(tx, success.get());
                    if (!committed && result.get().startsWith("ok:")) {
                        result.set(
                            "failed: rename_data address=" + safeValueForResponse(addressStr) +
                            " new_name=" + safeValueForResponse(newName) +
                            " error=transaction did not commit"
                        );
                    }
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
            return "failed: rename_data address=" + safeValueForResponse(addressStr) +
                " new_name=" + safeValueForResponse(newName) +
                " error=" + safeValueForResponse(e.getMessage());
        }

        return result.get();
    }

    private String getSymbolAt(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "failed: get_symbol_at no program loaded";
        if (addressStr == null || addressStr.isBlank()) return "failed: get_symbol_at address is required";

        Address addr = program.getAddressFactory().getAddress(addressStr);
        if (addr == null) return "failed: get_symbol_at invalid address=" + safeValueForResponse(addressStr);

        Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
        boolean hasDefinedData = program.getListing().getDefinedDataAt(addr) != null;
        if (symbol == null) {
            return "ok: get_symbol_at address=" + safeValueForResponse(addr.toString()) +
                " symbol=<none> defined_data=" + hasDefinedData;
        }

        return "ok: get_symbol_at address=" + safeValueForResponse(addr.toString()) +
            " symbol=" + safeValueForResponse(symbol.getName()) +
            " source=" + safeValueForResponse(symbol.getSource().toString()) +
            " symbol_type=" + safeValueForResponse(symbol.getSymbolType().toString()) +
            " defined_data=" + hasDefinedData;
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private String safeValueForResponse(String value) {
        if (value == null || value.isBlank()) {
            return "<empty>";
        }
        return value;
    }

    private String previewForResponse(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String normalized = value.replace("\r", " ").replace("\n", " ").trim();
        if (normalized.length() <= 120) {
            return normalized;
        }
        return normalized.substring(0, 117) + "...";
    }

    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, func, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, Function func, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            List<String> candidates = buildPrototypeCandidates(prototype);
            StringBuilder attemptLog = new StringBuilder();

            for (String candidate : candidates) {
                try {
                    ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, candidate);

                    if (sig == null) {
                        attemptLog.append("candidate rejected: \"")
                            .append(previewForResponse(candidate))
                            .append("\"\n");
                        continue;
                    }

                    ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                        new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                            addr, sig, SourceType.USER_DEFINED);

                    boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());
                    if (cmdResult) {
                        success.set(true);
                        Msg.info(this, "Successfully applied function signature");
                        if (!prototype.equals(candidate)) {
                            errorMessage.append("applied with normalized signature: ")
                                .append(candidate);
                        }
                        return;
                    }

                    attemptLog.append("candidate apply failed: \"")
                        .append(previewForResponse(candidate))
                        .append("\" -> ")
                        .append(cmd.getStatusMsg())
                        .append("\n");
                } catch (Exception candidateEx) {
                    attemptLog.append("candidate parse failed: \"")
                        .append(previewForResponse(candidate))
                        .append("\" -> ")
                        .append(candidateEx.getMessage())
                        .append("\n");
                }
            }

            errorMessage.append("Unable to parse/apply function prototype.");
            if (attemptLog.length() > 0) {
                errorMessage.append("\nAttempts:\n").append(attemptLog);
            }
            errorMessage.append("Accepted template example: void ")
                .append(func.getName())
                .append("(void)");
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    private List<String> buildPrototypeCandidates(String prototype) {
        LinkedHashSet<String> candidates = new LinkedHashSet<>();
        String original = normalizeWhitespace(prototype);
        if (!original.isBlank()) {
            candidates.add(original);
        }

        String mappedLegacy = normalizeLegacyCallingConventions(original, true);
        if (!mappedLegacy.isBlank()) {
            candidates.add(mappedLegacy);
        }

        String strippedLegacy = normalizeLegacyCallingConventions(original, false);
        if (!strippedLegacy.isBlank()) {
            candidates.add(strippedLegacy);
        }

        return new ArrayList<>(candidates);
    }

    private String normalizeWhitespace(String value) {
        if (value == null) {
            return "";
        }
        return value.replaceAll("\\s+", " ").trim();
    }

    private String normalizeLegacyCallingConventions(String prototype, boolean mapToCdecl) {
        if (prototype == null || prototype.isBlank()) {
            return "";
        }

        String normalized = prototype;
        String[] legacyToCdecl = {
            "__cdecl16far", "__cdecl16near", "__cdecl16",
            "__stdcall16far", "__stdcall16near", "__stdcall16",
            "__pascal16far", "__pascal16near", "__pascal16"
        };

        for (String token : legacyToCdecl) {
            normalized = normalized.replaceAll("(?i)\\b" + Pattern.quote(token) + "\\b", mapToCdecl ? "__cdecl" : " ");
        }

        String[] removeOnly = {
            "__far", "__near", "__huge", "far", "near", "huge",
            "__interrupt", "__loadds", "__saveregs", "__export"
        };

        for (String token : removeOnly) {
            normalized = normalized.replaceAll("(?i)\\b" + Pattern.quote(token) + "\\b", " ");
        }

        return normalizeWhitespace(normalized);
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                Function toFunc = program.getFunctionManager().getFunctionContaining(addr);

                refs.add(String.format(
                    "from=%s\tfrom_function=%s\tto=%s\tto_function=%s\tref_type=%s\tref_kind=%s\top_index=%d\tprimary=%s",
                    fromAddr,
                    safeFunctionName(fromFunc),
                    addr,
                    safeFunctionName(toFunc),
                    refType.getName(),
                    classifyRefKind(refType),
                    ref.getOperandIndex(),
                    ref.isPrimary()
                ));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = program.getFunctionManager().getFunctionContaining(addr);
                Function toFunc = program.getFunctionManager().getFunctionContaining(toAddr);

                refs.add(String.format(
                    "from=%s\tfrom_function=%s\tto=%s\tto_function=%s\tref_type=%s\tref_kind=%s\top_index=%d\tprimary=%s",
                    addr,
                    safeFunctionName(fromFunc),
                    toAddr,
                    safeFunctionName(toFunc),
                    refType.getName(),
                    classifyRefKind(refType),
                    ref.getOperandIndex(),
                    ref.isPrimary()
                ));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    private String safeFunctionName(Function function) {
        if (function == null) {
            return "<none>";
        }
        String name = function.getName();
        if (name == null || name.isBlank()) {
            return "<unnamed>";
        }
        return name;
    }

    private String classifyRefKind(RefType refType) {
        if (refType == null) {
            return "other";
        }
        if (refType.isCall()) {
            return "call";
        }
        if (refType.isJump()) {
            return "jump";
        }
        if (refType.isRead()) {
            return "read";
        }
        if (refType.isWrite()) {
            return "write";
        }
        return "other";
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    private String createFunctionByAddress(String entryStr, String name, String bodyStartStr, String bodyEndStr, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (entryStr == null || bodyStartStr == null || bodyEndStr == null) {
            return "entry, body_start and body_end are required";
        }

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder message = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function by address");
                try {
                    Address entry = program.getAddressFactory().getAddress(entryStr);
                    Address bodyStart = program.getAddressFactory().getAddress(bodyStartStr);
                    Address bodyEnd = program.getAddressFactory().getAddress(bodyEndStr);
                    if (entry == null || bodyStart == null || bodyEnd == null) {
                        message.append("Invalid address");
                        return;
                    }
                    if (bodyEnd.compareTo(bodyStart) < 0) {
                        message.append("body_end must be >= body_start");
                        return;
                    }

                    String functionName = (name == null || name.isBlank()) ? "sub_" + entry : name;
                    AddressSet body = new AddressSet(bodyStart, bodyEnd);
                    Function created = program.getFunctionManager().createFunction(functionName, entry, body, SourceType.USER_DEFINED);
                    if (created == null) {
                        message.append("Function creation returned null");
                        return;
                    }

                    if (comment != null && !comment.isBlank()) {
                        program.getListing().setComment(entry, CodeUnit.PRE_COMMENT, comment);
                    }

                    success.set(true);
                    message.append("Created function ").append(created.getName()).append(" at ").append(created.getEntryPoint())
                        .append(" body ").append(created.getBody().getMinAddress()).append(" - ").append(created.getBody().getMaxAddress());
                } catch (Exception e) {
                    message.append("Error creating function: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to create function on Swing thread: " + e.getMessage();
        }
        return message.toString();
    }

    private String deleteFunctionByAddress(String entryStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (entryStr == null || entryStr.isBlank()) return "entry is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder message = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete function by address");
                try {
                    Address entry = program.getAddressFactory().getAddress(entryStr);
                    if (entry == null) {
                        message.append("Invalid address");
                        return;
                    }
                    Function existing = program.getFunctionManager().getFunctionAt(entry);
                    if (existing == null) {
                        message.append("No function found at entry ").append(entryStr);
                        return;
                    }
                    boolean removed = program.getFunctionManager().removeFunction(entry);
                    success.set(removed);
                    message.append(removed ? "Deleted function at " + entry : "Failed to delete function at " + entry);
                } catch (Exception e) {
                    message.append("Error deleting function: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to delete function on Swing thread: " + e.getMessage();
        }
        return message.toString();
    }

    private String getFunctionContaining(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isBlank()) return "address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address";
            Function func = program.getFunctionManager().getFunctionContaining(addr);
            if (func == null) return "No function contains address " + addressStr;
            return String.format("Function: %s at %s\nContains: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                addr,
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting containing function: " + e.getMessage();
        }
    }

    private String readRegion(String startStr, String endStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (startStr == null || endStr == null) return "start and end are required";

        try {
            Address start = program.getAddressFactory().getAddress(startStr);
            Address end = program.getAddressFactory().getAddress(endStr);
            if (start == null || end == null) return "Invalid start or end address";
            if (end.compareTo(start) < 0) return "end must be >= start";

            long sizeLong = end.subtract(start) + 1;
            if (sizeLong <= 0 || sizeLong > 1024 * 1024) {
                return "Requested region size is out of supported range (1..1048576 bytes)";
            }

            Memory memory = program.getMemory();
            int size = (int) sizeLong;
            byte[] data = new byte[size];
            int bytesRead = memory.getBytes(start, data);
            if (bytesRead <= 0) {
                return "No bytes could be read from region";
            }

            return formatRegionHexDump(start, data, bytesRead);
        } catch (MemoryAccessException e) {
            return "Memory access error: " + e.getMessage();
        } catch (Exception e) {
            return "Error reading region: " + e.getMessage();
        }
    }

    private String formatRegionHexDump(Address start, byte[] data, int size) {
        StringBuilder out = new StringBuilder();
        out.append("start=").append(start).append(" size=").append(size).append("\n");
        for (int i = 0; i < size; i += 16) {
            int rowLen = Math.min(16, size - i);
            Address rowAddr = start.add(i);
            out.append(rowAddr).append(": ");
            for (int j = 0; j < rowLen; j++) {
                out.append(String.format("%02x", data[i + j] & 0xff));
                if (j + 1 < rowLen) {
                    out.append(' ');
                }
            }
            out.append("\n");
        }
        return out.toString();
    }

    private String disassembleRegion(String startStr, String endStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (startStr == null || endStr == null) return "start and end are required";

        try {
            Address start = program.getAddressFactory().getAddress(startStr);
            Address end = program.getAddressFactory().getAddress(endStr);
            if (start == null || end == null) return "Invalid start or end address";
            if (end.compareTo(start) < 0) return "end must be >= start";

            Listing listing = program.getListing();
            InstructionIterator it = listing.getInstructions(start, true);
            StringBuilder out = new StringBuilder();
            while (it.hasNext()) {
                Instruction ins = it.next();
                if (ins.getAddress().compareTo(end) > 0) {
                    break;
                }
                out.append(formatInstructionLine(program, ins)).append("\n");
            }

            return out.length() == 0 ? "No instructions found in range" : out.toString();
        } catch (Exception e) {
            return "Error disassembling region: " + e.getMessage();
        }
    }

    private String getInstructionWindow(String addressStr, int beforeCount, int afterCount) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isBlank()) return "address is required";

        try {
            Listing listing = program.getListing();
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address";

            Instruction center = listing.getInstructionContaining(addr);
            if (center == null) {
                center = listing.getInstructionAt(addr);
            }
            if (center == null) return "No instruction at or containing address " + addressStr;

            List<Instruction> before = new ArrayList<>();
            Instruction cursor = center;
            for (int i = 0; i < Math.max(0, beforeCount); i++) {
                cursor = listing.getInstructionBefore(cursor.getAddress());
                if (cursor == null) {
                    break;
                }
                before.add(cursor);
            }
            Collections.reverse(before);

            StringBuilder out = new StringBuilder();
            for (Instruction ins : before) {
                out.append(formatInstructionLine(program, ins)).append("\n");
            }
            out.append(">>> ").append(formatInstructionLine(program, center)).append("\n");

            cursor = center;
            for (int i = 0; i < Math.max(0, afterCount); i++) {
                cursor = listing.getInstructionAfter(cursor.getAddress());
                if (cursor == null) {
                    break;
                }
                out.append(formatInstructionLine(program, cursor)).append("\n");
            }

            return out.toString();
        } catch (Exception e) {
            return "Error reading instruction window: " + e.getMessage();
        }
    }

    private String searchInstructions(String query, String mode, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (query == null || query.isBlank()) return "query is required";

        String searchMode = (mode == null || mode.isBlank()) ? "text" : mode.toLowerCase(Locale.ROOT);
        int maxResults = Math.max(1, Math.min(limit, 5000));

        Listing listing = program.getListing();
        InstructionIterator it = listing.getInstructions(true);
        List<String> matches = new ArrayList<>();
        String needle = query.toLowerCase(Locale.ROOT);

        while (it.hasNext() && matches.size() < maxResults) {
            Instruction ins = it.next();
            if (instructionMatches(ins, needle, searchMode)) {
                matches.add(formatInstructionLine(program, ins));
            }
        }

        if (matches.isEmpty()) {
            return "No matching instructions found";
        }
        return String.join("\n", matches);
    }

    private boolean instructionMatches(Instruction ins, String needle, String mode) {
        String rendered = ins.toString().toLowerCase(Locale.ROOT);
        if ("text".equals(mode)) {
            return rendered.contains(needle) || ins.getAddress().toString().toLowerCase(Locale.ROOT).contains(needle);
        }

        if ("address".equals(mode)) {
            if (ins.getAddress().toString().toLowerCase(Locale.ROOT).contains(needle)) {
                return true;
            }
            int operandCount = ins.getNumOperands();
            for (int i = 0; i < operandCount; i++) {
                Address operandAddr = ins.getAddress(i);
                if (operandAddr != null && operandAddr.toString().toLowerCase(Locale.ROOT).contains(needle)) {
                    return true;
                }
                String repr = safeOperandRepresentation(ins, i);
                if (repr.contains(needle)) {
                    return true;
                }
            }
            return false;
        }

        if ("operand".equals(mode)) {
            int operandCount = ins.getNumOperands();
            for (int i = 0; i < operandCount; i++) {
                String repr = safeOperandRepresentation(ins, i);
                if (repr.contains(needle)) {
                    return true;
                }
            }
            return false;
        }

        return rendered.contains(needle);
    }

    private String safeOperandRepresentation(Instruction ins, int operandIndex) {
        try {
            return ins.getDefaultOperandRepresentation(operandIndex).toLowerCase(Locale.ROOT);
        } catch (Exception ignored) {
            return "";
        }
    }

    private String getDataUses(String addressStr, boolean includeOperandScans, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isBlank()) return "address is required";

        LinkedHashSet<String> uses = new LinkedHashSet<>();

        String xrefs = getXrefsTo(addressStr, 0, Math.max(1, limit));
        if (xrefs != null && !xrefs.isBlank()) {
            for (String line : xrefs.split("\\r?\\n")) {
                if (!line.isBlank()) {
                    uses.add("xref: " + line);
                }
            }
        }

        if (includeOperandScans && uses.size() < limit) {
            String scanned = searchInstructions(addressStr, "address", limit);
            if (scanned != null && !scanned.isBlank() && !scanned.startsWith("No matching")) {
                for (String line : scanned.split("\\r?\\n")) {
                    if (!line.isBlank()) {
                        uses.add("scan: " + line);
                        if (uses.size() >= limit) {
                            break;
                        }
                    }
                }
            }
        }

        if (uses.isEmpty()) {
            return "No uses found for " + addressStr;
        }
        return String.join("\n", uses);
    }

    private String setCommentsBatch(String batch, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (batch == null || batch.isBlank()) return "batch is required";

        AtomicBoolean committed = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                int applied = 0;
                int failed = 0;
                try {
                    for (String line : batch.split("\\r?\\n")) {
                        if (line.isBlank()) {
                            continue;
                        }
                        String[] parts = line.split("\\t", 2);
                        if (parts.length != 2) {
                            failed++;
                            out.append("invalid line (expected address<TAB>comment): ").append(line).append("\n");
                            continue;
                        }
                        try {
                            Address addr = program.getAddressFactory().getAddress(parts[0].trim());
                            if (addr == null) {
                                failed++;
                                out.append("invalid address: ").append(parts[0]).append("\n");
                                continue;
                            }
                            program.getListing().setComment(addr, commentType, parts[1]);
                            applied++;
                        } catch (Exception e) {
                            failed++;
                            out.append("failed ").append(parts[0]).append(": ").append(e.getMessage()).append("\n");
                        }
                    }
                    committed.set(true);
                    out.append("applied=").append(applied).append(" failed=").append(failed);
                } finally {
                    program.endTransaction(tx, committed.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to apply batch comments on Swing thread: " + e.getMessage();
        }

        return out.toString();
    }

    private String renameFunctionsByAddressBatch(String batch) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (batch == null || batch.isBlank()) return "batch is required";

        AtomicBoolean committed = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename functions batch");
                int applied = 0;
                int failed = 0;
                try {
                    for (String line : batch.split("\\r?\\n")) {
                        if (line.isBlank()) {
                            continue;
                        }
                        String[] parts = line.split("\\t", 2);
                        if (parts.length != 2) {
                            failed++;
                            out.append("invalid line (expected address<TAB>name): ").append(line).append("\n");
                            continue;
                        }
                        try {
                            Address addr = program.getAddressFactory().getAddress(parts[0].trim());
                            Function func = getFunctionForAddress(program, addr);
                            if (func == null) {
                                failed++;
                                out.append("no function for ").append(parts[0]).append("\n");
                                continue;
                            }
                            func.setName(parts[1].trim(), SourceType.USER_DEFINED);
                            applied++;
                        } catch (Exception e) {
                            failed++;
                            out.append("failed ").append(parts[0]).append(": ").append(e.getMessage()).append("\n");
                        }
                    }
                    committed.set(true);
                    out.append("applied=").append(applied).append(" failed=").append(failed);
                } finally {
                    program.endTransaction(tx, committed.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to apply function rename batch on Swing thread: " + e.getMessage();
        }

        return out.toString();
    }

    private String applyProgramEditPlan(String plan, boolean dryRun) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (plan == null || plan.isBlank()) return "plan is required";

        StringBuilder out = new StringBuilder();
        int successCount = 0;
        int failCount = 0;

        String[] lines = plan.split("\\r?\\n");
        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            String[] parts = line.split("\\|", -1);
            String action = parts[0].trim().toLowerCase(Locale.ROOT);
            try {
                if ("rename_function_by_address".equals(action) && parts.length >= 3) {
                    if (dryRun) {
                        out.append("DRY-RUN rename_function_by_address ").append(parts[1]).append(" -> ").append(parts[2]).append("\n");
                        successCount++;
                    } else {
                        String result = renameFunctionByAddress(parts[1], parts[2]) ? "ok" : "failed";
                        out.append("rename_function_by_address ").append(parts[1]).append(": ").append(result).append("\n");
                        if ("ok".equals(result)) successCount++; else failCount++;
                    }
                    continue;
                }

                if ("set_disassembly_comment".equals(action) && parts.length >= 3) {
                    if (dryRun) {
                        out.append("DRY-RUN set_disassembly_comment ").append(parts[1]).append("\n");
                        successCount++;
                    } else {
                        boolean ok = setDisassemblyComment(parts[1], parts[2]);
                        out.append("set_disassembly_comment ").append(parts[1]).append(": ").append(ok ? "ok" : "failed").append("\n");
                        if (ok) successCount++; else failCount++;
                    }
                    continue;
                }

                if ("set_decompiler_comment".equals(action) && parts.length >= 3) {
                    if (dryRun) {
                        out.append("DRY-RUN set_decompiler_comment ").append(parts[1]).append("\n");
                        successCount++;
                    } else {
                        boolean ok = setDecompilerComment(parts[1], parts[2]);
                        out.append("set_decompiler_comment ").append(parts[1]).append(": ").append(ok ? "ok" : "failed").append("\n");
                        if (ok) successCount++; else failCount++;
                    }
                    continue;
                }

                if ("delete_function_by_address".equals(action) && parts.length >= 2) {
                    if (dryRun) {
                        out.append("DRY-RUN delete_function_by_address ").append(parts[1]).append("\n");
                        successCount++;
                    } else {
                        String result = deleteFunctionByAddress(parts[1]);
                        out.append("delete_function_by_address ").append(parts[1]).append(": ").append(result).append("\n");
                        if (result.startsWith("Deleted function")) successCount++; else failCount++;
                    }
                    continue;
                }

                if ("create_function_by_address".equals(action) && parts.length >= 5) {
                    String comment = parts.length >= 6 ? parts[5] : "";
                    if (dryRun) {
                        out.append("DRY-RUN create_function_by_address ").append(parts[1]).append("\n");
                        successCount++;
                    } else {
                        String result = createFunctionByAddress(parts[1], parts[2], parts[3], parts[4], comment);
                        out.append("create_function_by_address ").append(parts[1]).append(": ").append(result).append("\n");
                        if (result.startsWith("Created function")) successCount++; else failCount++;
                    }
                    continue;
                }

                failCount++;
                out.append("Unsupported or invalid plan line: ").append(line).append("\n");
            } catch (Exception e) {
                failCount++;
                out.append("Failed line '").append(line).append("': ").append(e.getMessage()).append("\n");
            }
        }

        out.append("summary success=").append(successCount).append(" failed=").append(failCount)
            .append(" dry_run=").append(dryRun);
        return out.toString();
    }

    private String reanalyzeRegion(String startStr, String endStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (startStr == null || endStr == null) return "start and end are required";

        try {
            Address start = program.getAddressFactory().getAddress(startStr);
            Address end = program.getAddressFactory().getAddress(endStr);
            if (start == null || end == null) return "Invalid start or end address";
            if (end.compareTo(start) < 0) return "end must be >= start";

            AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
            analysisManager.startAnalysis(new ConsoleTaskMonitor());
            return "Triggered analysis pass after region request " + start + " - " + end;
        } catch (Exception e) {
            return "Error during reanalysis: " + e.getMessage();
        }
    }

    private String patchBytesAndReanalyze(String startStr, String bytesStr, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (startStr == null || startStr.isBlank()) return "start is required";
        if (bytesStr == null || bytesStr.isBlank()) return "bytes is required";

        byte[] patchBytes;
        try {
            patchBytes = parseHexBytes(bytesStr);
        } catch (IllegalArgumentException e) {
            return "Invalid bytes: " + e.getMessage();
        }

        AtomicBoolean committed = new AtomicBoolean(false);
        StringBuilder out = new StringBuilder();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Patch bytes and reanalyze");
                try {
                    Address start = program.getAddressFactory().getAddress(startStr);
                    if (start == null) {
                        out.append("Invalid start address");
                        return;
                    }
                    program.getMemory().setBytes(start, patchBytes);
                    if (comment != null && !comment.isBlank()) {
                        program.getListing().setComment(start, CodeUnit.EOL_COMMENT, comment);
                    }
                    committed.set(true);
                    out.append("Patched ").append(patchBytes.length).append(" bytes at ").append(start);
                } catch (Exception e) {
                    out.append("Patch failed: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, committed.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Patch failed on Swing thread: " + e.getMessage();
        }

        if (!committed.get()) {
            return out.toString();
        }

        try {
            Address start = program.getAddressFactory().getAddress(startStr);
            Address end = start.add(patchBytes.length - 1L);
            String reanalysis = reanalyzeRegion(start.toString(), end.toString());
            return out.append("\n").append(reanalysis).toString();
        } catch (Exception e) {
            return out.append("\nReanalysis skipped: ").append(e.getMessage()).toString();
        }
    }

    private byte[] parseHexBytes(String bytesStr) {
        String cleaned = bytesStr.replace(",", " ").trim();
        if (cleaned.isEmpty()) {
            throw new IllegalArgumentException("empty byte string");
        }
        String[] parts = cleaned.split("\\s+");
        byte[] out = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i].toLowerCase(Locale.ROOT).replace("0x", "");
            if (p.length() == 1) {
                p = "0" + p;
            }
            if (p.length() != 2) {
                throw new IllegalArgumentException("invalid token: " + parts[i]);
            }
            out[i] = (byte) Integer.parseInt(p, 16);
        }
        return out;
    }

    private String analyzeFunctionBoundaries(String startStr, String endStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (startStr == null || endStr == null) return "start and end are required";

        try {
            Address start = program.getAddressFactory().getAddress(startStr);
            Address end = program.getAddressFactory().getAddress(endStr);
            if (start == null || end == null) return "Invalid start or end address";
            if (end.compareTo(start) < 0) return "end must be >= start";

            FunctionManager fm = program.getFunctionManager();
            List<Function> inRange = new ArrayList<>();
            AddressSet querySet = new AddressSet(start, end);
            Iterator<Function> overlapIt = fm.getFunctionsOverlapping(querySet);
            while (overlapIt.hasNext()) {
                inRange.add(overlapIt.next());
            }

            List<String> findings = new ArrayList<>();
            inRange.sort(Comparator.comparing(Function::getEntryPoint));

            for (int i = 0; i < inRange.size(); i++) {
                Function curr = inRange.get(i);
                findings.add(String.format("function %s @ %s body %s - %s",
                    curr.getName(),
                    curr.getEntryPoint(),
                    curr.getBody().getMinAddress(),
                    curr.getBody().getMaxAddress()));

                if (i + 1 < inRange.size()) {
                    Function next = inRange.get(i + 1);
                    if (curr.getBody().intersects(next.getBody())) {
                        findings.add(String.format("overlap warning: %s intersects %s",
                            curr.getName(), next.getName()));
                    }
                }
            }

            Listing listing = program.getListing();
            Address cursor = start;
            while (cursor != null && cursor.compareTo(end) <= 0) {
                Instruction ins = listing.getInstructionAt(cursor);
                if (ins == null) {
                    cursor = cursor.next();
                    continue;
                }
                Function owner = fm.getFunctionContaining(ins.getAddress());
                if (owner == null && looksLikeFunctionStart(ins)) {
                    findings.add("candidate entry: " + formatInstructionLine(program, ins));
                }
                cursor = ins.getMaxAddress().next();
            }

            if (findings.isEmpty()) {
                return "No function overlap warnings or candidate entries found";
            }
            return String.join("\n", findings);
        } catch (Exception e) {
            return "Error analyzing boundaries: " + e.getMessage();
        }
    }

    private boolean looksLikeFunctionStart(Instruction ins) {
        String mnemonic = ins.getMnemonicString();
        if (mnemonic == null) {
            return false;
        }
        String m = mnemonic.toLowerCase(Locale.ROOT);
        return "push".equals(m) || "enter".equals(m) || "stp".equals(m);
    }

    private String formatInstructionLine(Program program, Instruction ins) {
        String comment = program.getListing().getComment(CodeUnit.EOL_COMMENT, ins.getAddress());
        if (comment == null) {
            comment = "";
        }
        return String.format("%s: %s%s",
            ins.getAddress(),
            ins.toString(),
            comment.isBlank() ? "" : " ; " + comment);
    }

    private String getProjectAccessInfo() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder out = new StringBuilder();
        out.append("program=").append(program.getName()).append("\n");
        out.append("temporary=").append(program.isTemporary()).append("\n");
        out.append("changed=").append(program.isChanged()).append("\n");
        out.append("can_save=").append(program.canSave()).append("\n");

        ghidra.framework.model.DomainFile df = program.getDomainFile();
        if (df == null) {
            out.append("domain_file=<none>\n");
            return out.toString();
        }

        out.append("domain_file=").append(df.getPathname()).append("\n");
        out.append("domain_is_read_only=").append(df.isReadOnly()).append("\n");
        out.append("domain_is_versioned=").append(df.isVersioned()).append("\n");
        out.append("domain_is_open=").append(df.isOpen()).append("\n");
        out.append("domain_is_busy=").append(df.isBusy()).append("\n");
        out.append("domain_is_in_writable_project=").append(df.isInWritableProject()).append("\n");
        return out.toString();
    }

    private String openCurrentProgramReadonly(int version, boolean makeCurrent) {
        Program current = getCurrentProgram();
        if (current == null) return "No program loaded";

        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return "Program manager service not available";

        ghidra.framework.model.DomainFile df = current.getDomainFile();
        if (df == null) return "Current program has no domain file";

        int requestedVersion = version <= 0 ? ghidra.framework.model.DomainFile.DEFAULT_VERSION : version;
        try {
            ghidra.framework.model.DomainObject roObj =
                df.getReadOnlyDomainObject(this, requestedVersion, new ConsoleTaskMonitor());
            if (!(roObj instanceof Program)) {
                return "Read-only open did not return a Program";
            }

            Program roProgram = (Program) roObj;
            pm.openProgram(roProgram, makeCurrent ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_VISIBLE);
            return "Opened read-only program: " + roProgram.getName() + " version=" + requestedVersion;
        } catch (Exception e) {
            return "Failed to open read-only program: " + e.getMessage();
        }
    }

    private String runReadonlyScript(String scriptPath, String scriptText) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        boolean hasPath = scriptPath != null && !scriptPath.isBlank();
        boolean hasText = scriptText != null && !scriptText.isBlank();
        if (!hasPath && !hasText) {
            return "Provide script_path or script_text";
        }
        if (hasPath && hasText) {
            return "Provide only one of script_path or script_text";
        }

        generic.jar.ResourceFile scriptFile = null;
        boolean deleteAfterRun = false;
        try {
            if (hasPath) {
                scriptFile = resolveScriptPath(scriptPath);
                if (scriptFile == null || !scriptFile.exists()) {
                    return "Script file not found: " + scriptPath;
                }
            } else {
                validateReadonlyScriptText(scriptText);
                scriptFile = writeTempReadonlyScript(scriptText);
                deleteAfterRun = true;
            }

            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
            if (provider == null) {
                return "No script provider for file: " + scriptFile.getName();
            }

            StringWriter outputBuffer = new StringWriter();
            PrintWriter writer = new PrintWriter(outputBuffer, true);
            GhidraScript script = provider.getScriptInstance(scriptFile, writer);
            if (script == null) {
                return "Unable to load script";
            }

            validateReadonlyScriptText(loadScriptTextForValidation(scriptFile));

            GhidraState state = new GhidraState(
                tool,
                tool.getProject(),
                program,
                null,
                null,
                null);

            script.execute(state, new ConsoleTaskMonitor(), writer);

            String output = outputBuffer.toString();
            if (output.isBlank()) {
                return "Script executed with no output";
            }
            return output;
        } catch (Exception e) {
            return "Failed to run readonly script: " + e.getMessage();
        } finally {
            if (deleteAfterRun && scriptFile != null) {
                scriptFile.delete();
            }
        }
    }

    private generic.jar.ResourceFile resolveScriptPath(String scriptPath) {
        if (scriptPath == null || scriptPath.isBlank()) {
            return null;
        }

        generic.jar.ResourceFile byName = GhidraScriptUtil.findScriptByName(scriptPath);
        if (byName != null && byName.exists()) {
            return byName;
        }

        generic.jar.ResourceFile direct = new generic.jar.ResourceFile(scriptPath);
        if (direct.exists()) {
            return direct;
        }

        return null;
    }

    private generic.jar.ResourceFile writeTempReadonlyScript(String scriptText) throws IOException {
        generic.jar.ResourceFile userDir = GhidraScriptUtil.getUserScriptDirectory();
        if (userDir == null) {
            throw new IOException("Ghidra user script directory not available");
        }
        if (!userDir.exists()) {
            userDir.mkdir();
        }

        String filename = "mcp_readonly_" + System.currentTimeMillis() + ".py";
        generic.jar.ResourceFile scriptFile = new generic.jar.ResourceFile(userDir, filename);
        try (OutputStream os = scriptFile.getOutputStream()) {
            os.write(scriptText.getBytes(StandardCharsets.UTF_8));
        }
        return scriptFile;
    }

    private String loadScriptTextForValidation(generic.jar.ResourceFile scriptFile) throws IOException {
        try (java.io.InputStream is = scriptFile.getInputStream()) {
            byte[] bytes = is.readAllBytes();
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    private void validateReadonlyScriptText(String scriptText) {
        if (scriptText == null) {
            throw new IllegalArgumentException("script text is required");
        }

        String text = scriptText.toLowerCase(Locale.ROOT);
        String[] blockedTokens = new String[] {
            "starttransaction(",
            "endtransaction(",
            "setbytes(",
            "createfunction(",
            "removefunction(",
            "setcomment(",
            "setname(",
            "applyto(",
            "runcommand(",
            "delete("};

        for (String token : blockedTokens) {
            if (text.contains(token)) {
                throw new IllegalArgumentException("script rejected by readonly policy: token " + token);
            }
        }
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private boolean parseBooleanOrDefault(String val, boolean defaultValue) {
        if (val == null) {
            return defaultValue;
        }
        String normalized = val.trim().toLowerCase(Locale.ROOT);
        if ("1".equals(normalized) || "true".equals(normalized) || "yes".equals(normalized)) {
            return true;
        }
        if ("0".equals(normalized) || "false".equals(normalized) || "no".equals(normalized)) {
            return false;
        }
        return defaultValue;
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    private Program getFirstOpenProgram(ProgramManager pm) {
        if (pm == null) {
            return null;
        }

        try {
            Object openPrograms = ProgramManager.class.getMethod("getAllOpenPrograms").invoke(pm);
            if (openPrograms instanceof Program[]) {
                Program[] programs = (Program[]) openPrograms;
                for (Program program : programs) {
                    if (program != null) {
                        return program;
                    }
                }
            }
            else if (openPrograms instanceof Collection<?>) {
                Collection<?> programs = (Collection<?>) openPrograms;
                for (Object candidate : programs) {
                    if (candidate instanceof Program) {
                        return (Program) candidate;
                    }
                }
            }
        }
        catch (ReflectiveOperationException e) {
            Msg.debug(this, "ProgramManager#getAllOpenPrograms unavailable", e);
        }

        return null;
    }

    private Program resolveCurrentProgramOnSwingThread() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null) {
            Program current = pm.getCurrentProgram();
            if (current != null) {
                lastKnownProgram = current;
                return current;
            }
        }

        CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
        if (codeViewer != null) {
            ProgramLocation location = codeViewer.getCurrentLocation();
            if (location != null && location.getProgram() != null) {
                lastKnownProgram = location.getProgram();
                return location.getProgram();
            }
        }

        Program openProgram = getFirstOpenProgram(pm);
        if (openProgram != null) {
            lastKnownProgram = openProgram;
            return openProgram;
        }

        return lastKnownProgram;
    }

    public Program getCurrentProgram() {
        AtomicReference<Program> programRef = new AtomicReference<>();

        try {
            if (SwingUtilities.isEventDispatchThread()) {
                programRef.set(resolveCurrentProgramOnSwingThread());
            }
            else {
                SwingUtilities.invokeAndWait(() -> programRef.set(resolveCurrentProgramOnSwingThread()));
            }
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Msg.error(this, "Interrupted while resolving current program", e);
        }
        catch (InvocationTargetException e) {
            Msg.error(this, "Failed to resolve current program on Swing thread", e);
        }

        return programRef.get();
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
