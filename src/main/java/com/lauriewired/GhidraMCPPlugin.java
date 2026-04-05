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
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
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
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getAllFunctionNames(program, offset, limit)));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getAllClassNames(program, offset, limit)));
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
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getSymbolAt(program, address)));
        });

        server.createContext("/symbol_at", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getSymbolAt(program, address)));
        });

        server.createContext("/getSymbolAt", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getSymbolAt(program, address)));
        });

        server.createContext("/symbolAt", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getSymbolAt(program, address)));
        });

        server.createContext("/get_symbol", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getSymbolAt(program, address)));
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
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> listSegments(program, offset, limit)));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> listImports(program, offset, limit)));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> listExports(program, offset, limit)));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> listNamespaces(program, offset, limit)));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> listDefinedData(program, offset, limit)));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> searchFunctionsByName(program, searchTerm, offset, limit)));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getFunctionByAddress(program, address)));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, withReadTargetContext(qparams,
                this::listFunctions));
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> decompileFunctionByAddress(program, address)));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> disassembleFunction(program, address)));
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
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getFunctionContaining(program, address)));
        });

        server.createContext("/read_region", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String start = qparams.get("start");
            String end = qparams.get("end");
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> readRegion(program, start, end)));
        });

        server.createContext("/disassemble_region", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String start = qparams.get("start");
            String end = qparams.get("end");
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> disassembleRegion(program, start, end)));
        });

        server.createContext("/get_instruction_window", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int beforeCount = parseIntOrDefault(qparams.get("before_count"), 5);
            int afterCount = parseIntOrDefault(qparams.get("after_count"), 5);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getInstructionWindow(program, address, beforeCount, afterCount)));
        });

        server.createContext("/search_instructions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String query = qparams.get("query");
            String mode = qparams.get("mode");
            int limit = parseIntOrDefault(qparams.get("limit"), 200);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> searchInstructions(program, query, mode, limit)));
        });

        server.createContext("/get_data_uses", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            boolean includeOperandScans = parseBooleanOrDefault(qparams.get("include_operand_scans"), true);
            int limit = parseIntOrDefault(qparams.get("limit"), 200);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getDataUses(program, address, includeOperandScans, limit)));
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
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getXrefsTo(program, address, offset, limit)));
        });

        // Alias route for clients that use get_* naming for xref tools.
        server.createContext("/get_xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getXrefsTo(program, address, offset, limit)));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getXrefsFrom(program, address, offset, limit)));
        });

        // Alias route for clients that use get_* naming for xref tools.
        server.createContext("/get_xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getXrefsFrom(program, address, offset, limit)));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getFunctionXrefs(program, name, offset, limit)));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> listDefinedStrings(program, offset, limit, filter)));
        });

        server.createContext("/search_bytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            String start = qparams.get("start");
            String end = qparams.get("end");
            String segmentFilter = qparams.get("segment_filter");
            int maxHits = parseIntOrDefault(qparams.get("max_hits"), 100);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> searchBytes(program, pattern, start, end, segmentFilter, maxHits)));
        });

        server.createContext("/get_callers", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String target = qparams.get("target");
            boolean includeNear = parseBooleanOrDefault(qparams.get("include_near"), true);
            boolean includeFar = parseBooleanOrDefault(qparams.get("include_far"), true);
            boolean includeJumps = parseBooleanOrDefault(qparams.get("include_jumps"), true);
            int limit = parseIntOrDefault(qparams.get("limit"), 200);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getCallers(program, target, includeNear, includeFar, includeJumps, limit)));
        });

        server.createContext("/callers", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String target = qparams.get("target");
            boolean includeNear = parseBooleanOrDefault(qparams.get("include_near"), true);
            boolean includeFar = parseBooleanOrDefault(qparams.get("include_far"), true);
            boolean includeJumps = parseBooleanOrDefault(qparams.get("include_jumps"), true);
            int limit = parseIntOrDefault(qparams.get("limit"), 200);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> getCallers(program, target, includeNear, includeFar, includeJumps, limit)));
        });

        server.createContext("/list_project_programs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String projectDir = qparams.get("project_dir");
            String projectName = qparams.get("project_name");
            String folderPath = qparams.get("folder_path");
            boolean recursive = parseBooleanOrDefault(qparams.get("recursive"), true);
            sendResponse(exchange, listProjectPrograms(projectDir, projectName, folderPath, recursive));
        });

        server.createContext("/project_programs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String projectDir = qparams.get("project_dir");
            String projectName = qparams.get("project_name");
            String folderPath = qparams.get("folder_path");
            boolean recursive = parseBooleanOrDefault(qparams.get("recursive"), true);
            sendResponse(exchange, listProjectPrograms(projectDir, projectName, folderPath, recursive));
        });

        server.createContext("/compare_regions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String leftStart = qparams.get("left_start");
            String leftEnd = qparams.get("left_end");
            String rightStart = qparams.get("right_start");
            String rightEnd = qparams.get("right_end");
            String mode = qparams.get("mode");
            int maxDiffs = parseIntOrDefault(qparams.get("max_diffs"), 100);
            sendResponse(exchange, withDualTargetContexts(qparams, "left_", "right_",
                (leftProgram, rightProgram) -> compareRegions(
                    leftProgram, rightProgram, leftStart, leftEnd, rightStart, rightEnd, mode, maxDiffs)));
        });

        server.createContext("/compare_strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String filter = qparams.get("filter");
            int maxResults = parseIntOrDefault(qparams.get("max_results"), 200);
            sendResponse(exchange, withDualTargetContexts(qparams, "left_", "right_",
                (leftProgram, rightProgram) -> compareStrings(leftProgram, rightProgram, filter, maxResults)));
        });

        server.createContext("/compare_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String leftFunction = qparams.get("left_function");
            String rightFunction = qparams.get("right_function");
            String mode = qparams.get("mode");
            int limit = parseIntOrDefault(qparams.get("limit"), 200);
            sendResponse(exchange, withDualTargetContexts(qparams, "left_", "right_",
                (leftProgram, rightProgram) -> compareFunctions(
                    leftProgram, rightProgram, leftFunction, rightFunction, mode, limit)));
        });

        server.createContext("/port_symbols", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String mappings = params.get("mappings");
            String apply = params.get("apply");
            String provenanceCommentTemplate = params.get("provenance_comment_template");
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            sendResponse(exchange, portSymbols(params, mappings, apply, provenanceCommentTemplate, dryRun));
        });

        server.createContext("/create_namespace", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createNamespace(
                params.get("name"),
                params.get("parent_path"),
                params.get("kind"),
                params));
        });

        server.createContext("/create_class", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            params.put("kind", "class");
            sendResponse(exchange, createNamespace(
                params.get("name"),
                params.get("parent_path"),
                params.get("kind"),
                params));
        });

        server.createContext("/list_namespace_members", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String path = qparams.get("path");
            boolean includeChildNamespaces = parseBooleanOrDefault(qparams.get("include_child_namespaces"), false);
            boolean includeFunctions = parseBooleanOrDefault(qparams.get("include_functions"), true);
            boolean includeData = parseBooleanOrDefault(qparams.get("include_data"), true);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> listNamespaceMembers(program, path, includeChildNamespaces, includeFunctions, includeData)));
        });

        server.createContext("/move_symbol_to_namespace", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            sendResponse(exchange, moveSymbolToNamespace(
                params.get("symbol_address"),
                params.get("symbol_name"),
                params.get("namespace_path"),
                params.get("new_name"),
                params.get("conflict_policy"),
                dryRun,
                params));
        });

        server.createContext("/set_function_class", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            sendResponse(exchange, setFunctionClass(
                params.get("function_address"),
                params.get("class_path"),
                params.get("method_name"),
                params.get("this_param_name"),
                params.get("calling_convention"),
                dryRun,
                params));
        });

        server.createContext("/move_function_to_class", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            sendResponse(exchange, setFunctionClass(
                params.get("function_address"),
                params.get("class_path"),
                params.get("method_name"),
                params.get("this_param_name"),
                params.get("calling_convention"),
                dryRun,
                params));
        });

        server.createContext("/create_or_update_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            int size = parseIntOrDefault(params.get("size"), 0);
            int packing = parseIntOrDefault(params.get("packing"), 0);
            sendResponse(exchange, createOrUpdateStruct(
                params.get("name"),
                params.get("category_path"),
                size,
                packing,
                params.get("fields"),
                dryRun,
                params));
        });

        server.createContext("/create_or_update_vtable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            sendResponse(exchange, createOrUpdateVtable(
                params.get("name"),
                params.get("category_path"),
                params.get("slots"),
                dryRun,
                params));
        });

        server.createContext("/build_vtable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            sendResponse(exchange, createOrUpdateVtable(
                params.get("name"),
                params.get("category_path"),
                params.get("slots"),
                dryRun,
                params));
        });

        server.createContext("/set_function_this_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            sendResponse(exchange, setFunctionThisType(
                params.get("function_address"),
                params.get("this_type"),
                params.get("this_param_name"),
                params.get("this_storage"),
                params.get("calling_convention"),
                dryRun,
                params));
        });

        server.createContext("/set_this_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            sendResponse(exchange, setFunctionThisType(
                params.get("function_address"),
                params.get("this_type"),
                params.get("this_param_name"),
                params.get("this_storage"),
                params.get("calling_convention"),
                dryRun,
                params));
        });

        server.createContext("/analyze_vtable", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int slotCount = parseIntOrDefault(qparams.get("slot_count"), 0);
            boolean stopOnInvalidPointer = parseBooleanOrDefault(qparams.get("stop_on_invalid_pointer"), true);
            sendResponse(exchange, withReadTargetContext(qparams,
                program -> analyzeVtable(program, address, slotCount, stopOnInvalidPointer)));
        });

        server.createContext("/apply_class_layout", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            sendResponse(exchange, applyClassLayout(
                params.get("class_path"),
                params.get("instance_struct"),
                params.get("vtable_struct"),
                params.get("vtable_address"),
                params.get("methods"),
                dryRun,
                params));
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
            sendResponse(exchange, applyProgramEditPlan(plan, dryRun, params));
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
            sendResponse(exchange, patchBytesAndReanalyze(start, bytes, comment, params));
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

        server.createContext("/get_runtime_capabilities", exchange -> {
            sendResponse(exchange, getRuntimeCapabilities());
        });

        server.createContext("/runtime_capabilities", exchange -> {
            sendResponse(exchange, getRuntimeCapabilities());
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

        server.createContext("/run_write_script", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String scriptPath = params.get("script_path");
            String scriptText = params.get("script_text");
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            sendResponse(exchange, runWriteScript(scriptPath, scriptText, dryRun, params));
        });

        server.createContext("/run_transaction_script", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String scriptPath = params.get("script_path");
            String scriptText = params.get("script_text");
            boolean dryRun = parseBooleanOrDefault(params.get("dry_run"), false);
            sendResponse(exchange, runWriteScript(scriptPath, scriptText, dryRun, params));
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
        return getAllFunctionNames(getCurrentProgram(), offset, limit);
    }

    private String getAllFunctionNames(Program program, int offset, int limit) {
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        return getAllClassNames(getCurrentProgram(), offset, limit);
    }

    private String getAllClassNames(Program program, int offset, int limit) {
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
        return listSegments(getCurrentProgram(), offset, limit);
    }

    private String listSegments(Program program, int offset, int limit) {
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        return listImports(getCurrentProgram(), offset, limit);
    }

    private String listImports(Program program, int offset, int limit) {
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        return listExports(getCurrentProgram(), offset, limit);
    }

    private String listExports(Program program, int offset, int limit) {
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
        return listNamespaces(getCurrentProgram(), offset, limit);
    }

    private String listNamespaces(Program program, int offset, int limit) {
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
        return listDefinedData(getCurrentProgram(), offset, limit);
    }

    private String listDefinedData(Program program, int offset, int limit) {
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
        return searchFunctionsByName(getCurrentProgram(), searchTerm, offset, limit);
    }

    private String searchFunctionsByName(Program program, String searchTerm, int offset, int limit) {
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
        return getSymbolAt(getCurrentProgram(), addressStr);
    }

    private String getSymbolAt(Program program, String addressStr) {
        if (program == null) return "failed: get_symbol_at no program loaded";
        if (addressStr == null || addressStr.isBlank()) return "failed: get_symbol_at address is required";

        Address addr = parseAddress(program, addressStr);
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
        return getFunctionByAddress(getCurrentProgram(), addressStr);
    }

    private String getFunctionByAddress(Program program, String addressStr) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = parseAddress(program, addressStr);
            if (addr == null) return "Invalid address";
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
        return listFunctions(getCurrentProgram());
    }

    private String listFunctions(Program program) {
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
        if (program == null || addr == null) {
            return null;
        }
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    private Address parseAddress(Program program, String addressStr) {
        if (program == null || addressStr == null || addressStr.isBlank()) {
            return null;
        }

        String trimmed = addressStr.trim();
        Address addr = program.getAddressFactory().getAddress(trimmed);
        if (addr == null && trimmed.regionMatches(true, 0, "0x", 0, 2)) {
            addr = program.getAddressFactory().getAddress(trimmed.substring(2));
        }
        return addr;
    }

    private Function resolveFunctionIdentifier(Program program, String identifier) {
        if (program == null || identifier == null || identifier.isBlank()) {
            return null;
        }

        Address addr = parseAddress(program, identifier);
        if (addr != null) {
            return getFunctionForAddress(program, addr);
        }

        Function caseInsensitiveMatch = null;
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            if (identifier.equals(function.getName())) {
                return function;
            }
            if (caseInsensitiveMatch == null && identifier.equalsIgnoreCase(function.getName())) {
                caseInsensitiveMatch = function;
            }
        }
        return caseInsensitiveMatch;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        return decompileFunctionByAddress(getCurrentProgram(), addressStr);
    }

    private String decompileFunctionByAddress(Program program, String addressStr) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = parseAddress(program, addressStr);
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
        return disassembleFunction(getCurrentProgram(), addressStr);
    }

    private String disassembleFunction(Program program, String addressStr) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = parseAddress(program, addressStr);
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

    private static class ProgramTargetContext {
        private final Program program;
        private final Object ghidraProjectHandle;
        private final ghidra.framework.model.DomainFile domainFile;
        private final boolean explicitTarget;
        private final String targetSummary;
        private final String errorMessage;

        private ProgramTargetContext(Program program, Object ghidraProjectHandle,
                                     ghidra.framework.model.DomainFile domainFile,
                                     boolean explicitTarget, String targetSummary,
                                     String errorMessage) {
            this.program = program;
            this.ghidraProjectHandle = ghidraProjectHandle;
            this.domainFile = domainFile;
            this.explicitTarget = explicitTarget;
            this.targetSummary = targetSummary;
            this.errorMessage = errorMessage;
        }

        private static ProgramTargetContext current(Program program, String targetSummary) {
            return new ProgramTargetContext(program, null, program.getDomainFile(), false, targetSummary, null);
        }

        private static ProgramTargetContext explicit(Program program, Object ghidraProjectHandle,
                                                     ghidra.framework.model.DomainFile domainFile,
                                                     String targetSummary) {
            return new ProgramTargetContext(program, ghidraProjectHandle, domainFile, true, targetSummary, null);
        }

        private static ProgramTargetContext error(String errorMessage) {
            return new ProgramTargetContext(null, null, null, false, "", errorMessage);
        }

        private boolean hasError() {
            return errorMessage != null && !errorMessage.isBlank();
        }
    }

    private static class OperationResult {
        private final boolean success;
        private final String message;

        private OperationResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }

    private static class NamespaceResolutionResult {
        private final Namespace namespace;
        private final String errorMessage;

        private NamespaceResolutionResult(Namespace namespace, String errorMessage) {
            this.namespace = namespace;
            this.errorMessage = errorMessage;
        }

        private boolean hasError() {
            return errorMessage != null && !errorMessage.isBlank();
        }
    }

    private static class SymbolLookupResult {
        private final Symbol symbol;
        private final String errorMessage;

        private SymbolLookupResult(Symbol symbol, String errorMessage) {
            this.symbol = symbol;
            this.errorMessage = errorMessage;
        }

        private boolean hasError() {
            return errorMessage != null && !errorMessage.isBlank();
        }
    }

    private static class ReadonlyScriptCapability {
        private final boolean supported;
        private final String status;
        private final String reason;
        private final String detail;

        private ReadonlyScriptCapability(boolean supported, String status, String reason, String detail) {
            this.supported = supported;
            this.status = status;
            this.reason = reason;
            this.detail = detail;
        }
    }

    private static class WriteScriptCapability {
        private final boolean supported;
        private final String status;
        private final String reason;
        private final String detail;

        private WriteScriptCapability(boolean supported, String status, String reason, String detail) {
            this.supported = supported;
            this.status = status;
            this.reason = reason;
            this.detail = detail;
        }
    }

    @FunctionalInterface
    private interface ProgramTextQuery {
        String run(Program program);
    }

    @FunctionalInterface
    private interface DualProgramTextQuery {
        String run(Program leftProgram, Program rightProgram);
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String normalizeFolderPath(String folderPath) {
        String normalized = trimToNull(folderPath);
        if (normalized == null) {
            return "/";
        }
        normalized = normalized.replace('\\', '/');
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        if (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String prefixedParamKey(String prefix, String key) {
        String normalized = prefix == null ? "" : prefix;
        return normalized.isEmpty() ? key : normalized + key;
    }

    private String prefixedSummaryKey(String prefix, String key) {
        String normalized = prefix == null ? "" : prefix;
        if (normalized.endsWith("_")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized.isEmpty() ? key : normalized + "_" + key;
    }

    private boolean hasExplicitTargetSelectors(Map<String, String> params) {
        return hasExplicitTargetSelectors(params, "");
    }

    private boolean hasExplicitTargetSelectors(Map<String, String> params, String prefix) {
        if (params == null || params.isEmpty()) {
            return false;
        }
        return trimToNull(params.get(prefixedParamKey(prefix, "project_dir"))) != null ||
            trimToNull(params.get(prefixedParamKey(prefix, "project_name"))) != null ||
            trimToNull(params.get(prefixedParamKey(prefix, "folder_path"))) != null ||
            trimToNull(params.get(prefixedParamKey(prefix, "program_name"))) != null;
    }

    private Throwable unwrapReflectionFailure(Exception e) {
        if (e instanceof InvocationTargetException) {
            Throwable cause = ((InvocationTargetException) e).getCause();
            if (cause != null) {
                return cause;
            }
        }
        return e;
    }

    private Object openExplicitProjectHandle(String projectDir, String projectName) throws Exception {
        Class<?> ghidraProjectClass = Class.forName("ghidra.base.project.GhidraProject");
        return ghidraProjectClass.getMethod("openProject", String.class, String.class)
            .invoke(null, projectDir, projectName);
    }

    private ghidra.framework.model.ProjectData getProjectDataFromHandle(Object ghidraProjectHandle) {
        if (ghidraProjectHandle == null) {
            return null;
        }
        try {
            Object projectData = ghidraProjectHandle.getClass().getMethod("getProjectData").invoke(ghidraProjectHandle);
            return projectData instanceof ghidra.framework.model.ProjectData
                ? (ghidra.framework.model.ProjectData) projectData
                : null;
        } catch (Exception e) {
            Msg.debug(this, "Failed to resolve project data from explicit target handle", e);
            return null;
        }
    }

    private ghidra.framework.model.DomainFile resolveExplicitDomainFile(Object ghidraProjectHandle,
                                                                        String folderPath,
                                                                        String programName) {
        ghidra.framework.model.ProjectData projectData = getProjectDataFromHandle(ghidraProjectHandle);
        if (projectData == null) {
            return null;
        }

        ghidra.framework.model.DomainFolder folder = "/".equals(folderPath)
            ? projectData.getRootFolder()
            : projectData.getFolder(folderPath);
        if (folder == null) {
            return null;
        }
        return folder.getFile(programName);
    }

    private Program openExplicitProgramWritable(ghidra.framework.model.DomainFile domainFile) throws Exception {
        if (domainFile == null) {
            return null;
        }

        Object opened = domainFile.getOpenedDomainObject(this);
        if (opened instanceof Program) {
            return (Program) opened;
        }

        Object result = domainFile.getDomainObject(this, false, false, new ConsoleTaskMonitor());
        return result instanceof Program ? (Program) result : null;
    }

    private ghidra.framework.model.Project getProjectFromHandle(Object ghidraProjectHandle) {
        if (ghidraProjectHandle == null) {
            return null;
        }
        try {
            Object project = ghidraProjectHandle.getClass().getMethod("getProject").invoke(ghidraProjectHandle);
            return project instanceof ghidra.framework.model.Project
                ? (ghidra.framework.model.Project) project
                : null;
        } catch (Exception e) {
            Msg.debug(this, "Failed to resolve project from explicit target handle", e);
            return null;
        }
    }

    private boolean targetMatchesDomainFile(ghidra.framework.model.DomainFile domainFile,
                                            String projectDir, String projectName,
                                            String folderPath, String programName) {
        if (domainFile == null || programName == null || projectDir == null || projectName == null) {
            return false;
        }

        ghidra.framework.model.ProjectLocator locator = domainFile.getProjectLocator();
        if (locator == null) {
            return false;
        }

        String targetProjectDir = trimToNull(projectDir);
        String targetProjectName = trimToNull(projectName);
        String targetFolderPath = normalizeFolderPath(folderPath);

        if (!projectName.equals(locator.getName())) {
            return false;
        }
        if (!projectDir.equals(locator.getLocation())) {
            return false;
        }
        if (!programName.equals(domainFile.getName())) {
            return false;
        }

        ghidra.framework.model.DomainFolder parent = domainFile.getParent();
        String actualFolderPath = parent == null ? "/" : normalizeFolderPath(parent.getPathname());
        return targetFolderPath.equals(actualFolderPath);
    }

    private Program findMatchingOpenProgram(String projectDir, String projectName,
                                            String folderPath, String programName) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            return null;
        }

        Program current = pm.getCurrentProgram();
        if (current != null && targetMatchesDomainFile(current.getDomainFile(), projectDir, projectName, folderPath, programName)) {
            return current;
        }

        for (Program openProgram : pm.getAllOpenPrograms()) {
            if (openProgram == null) {
                continue;
            }
            if (targetMatchesDomainFile(openProgram.getDomainFile(), projectDir, projectName, folderPath, programName)) {
                return openProgram;
            }
        }

        return null;
    }

    private ProgramTargetContext resolveTargetContext(Map<String, String> params, String prefix) {
        if (!hasExplicitTargetSelectors(params, prefix)) {
            Program program = getCurrentProgram();
            if (program == null) {
                return ProgramTargetContext.error("No program loaded");
            }
            return ProgramTargetContext.current(
                program,
                prefixedSummaryKey(prefix, "current_program") + "=" + program.getName());
        }

        String projectDir = trimToNull(params.get(prefixedParamKey(prefix, "project_dir")));
        String projectName = trimToNull(params.get(prefixedParamKey(prefix, "project_name")));
        String programName = trimToNull(params.get(prefixedParamKey(prefix, "program_name")));
        String folderPath = normalizeFolderPath(params.get(prefixedParamKey(prefix, "folder_path")));

        List<String> missing = new ArrayList<>();
        if (projectDir == null) {
            missing.add(prefixedParamKey(prefix, "project_dir"));
        }
        if (projectName == null) {
            missing.add(prefixedParamKey(prefix, "project_name"));
        }
        if (programName == null) {
            missing.add(prefixedParamKey(prefix, "program_name"));
        }
        if (!missing.isEmpty()) {
            return ProgramTargetContext.error(
                "Explicit target selection requires: " + String.join(", ", missing));
        }

        String summary = prefixedSummaryKey(prefix, "target_project_dir") + "=" + projectDir + "\n"
            + prefixedSummaryKey(prefix, "target_project_name") + "=" + projectName + "\n"
            + prefixedSummaryKey(prefix, "target_folder_path") + "=" + folderPath + "\n"
            + prefixedSummaryKey(prefix, "target_program_name") + "=" + programName;

        Program openProgram = findMatchingOpenProgram(projectDir, projectName, folderPath, programName);
        if (openProgram != null) {
            return ProgramTargetContext.current(openProgram,
                summary + "\n" + prefixedSummaryKey(prefix, "target_resolution") + "=reused_open_program");
        }

        Object ghidraProjectHandle = null;
        try {
            ghidraProjectHandle = openExplicitProjectHandle(projectDir, projectName);
            ghidra.framework.model.DomainFile domainFile = resolveExplicitDomainFile(ghidraProjectHandle, folderPath, programName);
            Program program = openExplicitProgramWritable(domainFile);
            if (program == null) {
                ghidra.framework.model.Project project = getProjectFromHandle(ghidraProjectHandle);
                if (project != null && !project.isClosed()) {
                    project.close();
                }
                return ProgramTargetContext.error(
                    "Failed to open target program " + folderPath + "/" + programName);
            }

            return ProgramTargetContext.explicit(
                program,
                ghidraProjectHandle,
                domainFile,
                summary + "\n" + prefixedSummaryKey(prefix, "target_resolution") + "=open_writable_domain_object");
        } catch (Exception e) {
            ghidra.framework.model.Project project = getProjectFromHandle(ghidraProjectHandle);
            if (project != null) {
                try {
                    if (!project.isClosed()) {
                        project.close();
                    }
                } catch (Exception closeIgnored) {
                    Msg.debug(this, "Failed to close explicit target project after open failure", closeIgnored);
                }
            }
            Throwable cause = unwrapReflectionFailure(e);
            return ProgramTargetContext.error("Failed to open explicit target: " + cause.getMessage());
        }
    }

    private ProgramTargetContext resolveWriteTargetContext(Map<String, String> params) {
        return resolveTargetContext(params, "");
    }

    private ProgramTargetContext resolveReadTargetContext(Map<String, String> params) {
        return resolveTargetContext(params, "");
    }

    private void closeWriteTargetContext(ProgramTargetContext context) {
        if (context == null || !context.explicitTarget) {
            return;
        }

        if (context.program != null) {
            try {
                context.program.release(this);
            } catch (Exception e) {
                Msg.debug(this, "Failed to release explicit target program", e);
            }
        }

        ghidra.framework.model.Project project = getProjectFromHandle(context.ghidraProjectHandle);
        if (project != null) {
            try {
                project.releaseFiles(this);
            } catch (Exception e) {
                Msg.debug(this, "Failed to release explicit target project files", e);
            }
            try {
                if (!project.isClosed()) {
                    project.close();
                }
            } catch (Exception e) {
                Msg.debug(this, "Failed to close explicit target project", e);
            }
        }
    }

    private String saveExplicitTargetIfNeeded(ProgramTargetContext context) {
        if (context == null || !context.explicitTarget) {
            return "save_mode=current_context";
        }
        try {
            if (context.domainFile != null) {
                context.domainFile.save(new ConsoleTaskMonitor());
            } else {
                context.ghidraProjectHandle.getClass().getMethod("save", Program.class)
                    .invoke(context.ghidraProjectHandle, context.program);
            }
            return "saved_explicit_target=true";
        } catch (Exception e) {
            Throwable cause = unwrapReflectionFailure(e);
            return "saved_explicit_target=false\nsave_error=" + escapeNonAscii(cause.getMessage());
        }
    }

    private String formatTargetedResponse(ProgramTargetContext context, String body) {
        if (context == null) {
            return body;
        }
        if (!context.explicitTarget) {
            return body;
        }
        if (context.targetSummary == null || context.targetSummary.isBlank()) {
            return body;
        }
        if (body == null || body.isBlank()) {
            return context.targetSummary;
        }
        return context.targetSummary + "\n" + body;
    }

    private String formatDualTargetedResponse(ProgramTargetContext leftContext,
                                              ProgramTargetContext rightContext,
                                              String body) {
        StringBuilder out = new StringBuilder();
        if (leftContext != null && leftContext.explicitTarget && leftContext.targetSummary != null && !leftContext.targetSummary.isBlank()) {
            out.append(leftContext.targetSummary);
        }
        if (rightContext != null && rightContext.explicitTarget && rightContext.targetSummary != null && !rightContext.targetSummary.isBlank()) {
            if (out.length() > 0) {
                out.append("\n");
            }
            out.append(rightContext.targetSummary);
        }
        if (body != null && !body.isBlank()) {
            if (out.length() > 0) {
                out.append("\n");
            }
            out.append(body);
        }
        return out.toString();
    }

    private String withReadTargetContext(Map<String, String> params, ProgramTextQuery query) {
        ProgramTargetContext context = resolveReadTargetContext(params);
        if (context.hasError()) {
            return context.errorMessage;
        }

        try {
            return formatTargetedResponse(context, query.run(context.program));
        } finally {
            closeWriteTargetContext(context);
        }
    }

    private String withDualTargetContexts(Map<String, String> params, String leftPrefix,
                                          String rightPrefix, DualProgramTextQuery query) {
        ProgramTargetContext leftContext = resolveTargetContext(params, leftPrefix);
        if (leftContext.hasError()) {
            return leftContext.errorMessage;
        }

        ProgramTargetContext rightContext = resolveTargetContext(params, rightPrefix);
        if (rightContext.hasError()) {
            closeWriteTargetContext(leftContext);
            return rightContext.errorMessage;
        }

        try {
            return formatDualTargetedResponse(
                leftContext,
                rightContext,
                query.run(leftContext.program, rightContext.program));
        } finally {
            closeWriteTargetContext(leftContext);
            closeWriteTargetContext(rightContext);
        }
    }

    private String createNamespace(String name, String parentPath, String kind, Map<String, String> params) {
        ProgramTargetContext context = resolveWriteTargetContext(params);
        if (context.hasError()) {
            return context.errorMessage;
        }

        AtomicReference<OperationResult> resultRef = new AtomicReference<>(new OperationResult(false, "create_namespace failed"));
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = context.program.startTransaction("Create namespace");
                boolean commit = false;
                try {
                    OperationResult result = createNamespaceInProgram(context.program, name, parentPath, kind);
                    resultRef.set(result);
                    commit = result.success;
                } finally {
                    context.program.endTransaction(tx, commit);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultRef.set(new OperationResult(false, "Failed to create namespace on Swing thread: " + e.getMessage()));
        }

        try {
            String response = formatTargetedResponse(context, resultRef.get().message);
            if (resultRef.get().success && context.explicitTarget) {
                response = response + "\n" + saveExplicitTargetIfNeeded(context);
            }
            return response;
        } finally {
            closeWriteTargetContext(context);
        }
    }

    private OperationResult createNamespaceInProgram(Program program, String name, String parentPath, String kind) {
        String normalizedName = trimToNull(name);
        if (normalizedName == null) {
            return new OperationResult(false, "name is required");
        }

        String normalizedKind = trimToNull(kind);
        if (normalizedKind == null) {
            normalizedKind = "namespace";
        }
        normalizedKind = normalizedKind.toLowerCase(Locale.ROOT);
        if (!normalizedKind.equals("namespace") && !normalizedKind.equals("class")) {
            return new OperationResult(false, "kind must be namespace or class");
        }

        NamespaceResolutionResult parentResult = resolveNamespacePath(program, parentPath, false, false);
        if (parentResult.hasError()) {
            return new OperationResult(false, parentResult.errorMessage);
        }

        Namespace parentNamespace = parentResult.namespace == null ? program.getGlobalNamespace() : parentResult.namespace;
        SymbolTable symbolTable = program.getSymbolTable();
        Namespace existing = findChildNamespace(symbolTable, parentNamespace, normalizedName);
        if (existing != null) {
            return new OperationResult(true,
                "status=exists\ncreated=false\nkind=" + namespaceKind(existing) + "\npath=" + namespacePath(existing));
        }

        try {
            Namespace created = normalizedKind.equals("class")
                ? symbolTable.createClass(parentNamespace, normalizedName, SourceType.USER_DEFINED)
                : symbolTable.createNameSpace(parentNamespace, normalizedName, SourceType.USER_DEFINED);
            return new OperationResult(true,
                "status=ok\ncreated=true\nkind=" + normalizedKind + "\npath=" + namespacePath(created)
                    + "\nsymbol_id=" + created.getSymbol().getID());
        } catch (DuplicateNameException | InvalidInputException e) {
            return new OperationResult(false, "Failed to create namespace: " + e.getMessage());
        }
    }

    private String listNamespaceMembers(Program program, String path, boolean includeChildNamespaces,
                                        boolean includeFunctions, boolean includeData) {
        NamespaceResolutionResult namespaceResult = resolveNamespacePath(program, path, false, false);
        if (namespaceResult.hasError()) {
            return namespaceResult.errorMessage;
        }

        Namespace namespace = namespaceResult.namespace;
        if (namespace == null) {
            return "path is required";
        }

        List<String> lines = new ArrayList<>();
        SymbolIterator iterator = program.getSymbolTable().getSymbols(namespace);
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            if (symbol == null || symbol.isDeleted()) {
                continue;
            }

            SymbolType symbolType = symbol.getSymbolType();
            boolean isNamespace = symbolType == SymbolType.NAMESPACE || symbolType == SymbolType.CLASS;
            if (isNamespace && !includeChildNamespaces) {
                continue;
            }
            if (symbolType == SymbolType.FUNCTION && !includeFunctions) {
                continue;
            }
            if (!isNamespace && symbolType != SymbolType.FUNCTION && !includeData) {
                continue;
            }

            String datatype = "";
            if (symbol.getAddress() != null) {
                Data data = program.getListing().getDefinedDataAt(symbol.getAddress());
                if (data != null && data.getDataType() != null) {
                    datatype = data.getDataType().getPathName();
                }
            }

            lines.add("member_kind=" + symbolType
                + "\tname=" + safeValueForResponse(symbol.getName())
                + "\taddress=" + safeValueForResponse(symbol.getAddress() == null ? "" : symbol.getAddress().toString())
                + "\tdatatype=" + safeValueForResponse(datatype)
                + "\tpath=" + safeValueForResponse(symbolPath(symbol)));
        }

        return "status=ok\npath=" + namespacePath(namespace)
            + "\nmember_count=" + lines.size()
            + (lines.isEmpty() ? "" : "\n" + String.join("\n", lines));
    }

    private String moveSymbolToNamespace(String symbolAddress, String symbolName, String namespacePath,
                                         String newName, String conflictPolicy, boolean dryRun,
                                         Map<String, String> params) {
        ProgramTargetContext context = resolveWriteTargetContext(params);
        if (context.hasError()) {
            return context.errorMessage;
        }

        AtomicReference<OperationResult> resultRef = new AtomicReference<>(new OperationResult(false, "move_symbol_to_namespace failed"));
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = context.program.startTransaction("Move symbol to namespace");
                boolean commit = false;
                try {
                    OperationResult result = moveSymbolToNamespaceInProgram(
                        context.program, symbolAddress, symbolName, namespacePath, newName, conflictPolicy, dryRun);
                    resultRef.set(result);
                    commit = result.success && !dryRun;
                } finally {
                    context.program.endTransaction(tx, commit);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultRef.set(new OperationResult(false, "Failed to move symbol on Swing thread: " + e.getMessage()));
        }

        try {
            String response = formatTargetedResponse(context, resultRef.get().message);
            if (resultRef.get().success && context.explicitTarget && !dryRun) {
                response = response + "\n" + saveExplicitTargetIfNeeded(context);
            }
            return response;
        } finally {
            closeWriteTargetContext(context);
        }
    }

    private OperationResult moveSymbolToNamespaceInProgram(Program program, String symbolAddress,
                                                           String symbolName, String namespacePath,
                                                           String newName, String conflictPolicy,
                                                           boolean dryRun) {
        SymbolLookupResult symbolResult = resolveMovableSymbol(program, symbolAddress, symbolName);
        if (symbolResult.hasError()) {
            return new OperationResult(false, symbolResult.errorMessage);
        }

        NamespaceResolutionResult namespaceResult = resolveNamespacePath(program, namespacePath, true, true);
        if (namespaceResult.hasError()) {
            return new OperationResult(false, namespaceResult.errorMessage);
        }

        Symbol symbol = symbolResult.symbol;
        Namespace targetNamespace = namespaceResult.namespace;
        String policy = trimToNull(conflictPolicy);
        if (policy == null) {
            policy = "fail";
        }
        policy = policy.toLowerCase(Locale.ROOT);
        if (!policy.equals("fail") && !policy.equals("keep_existing") && !policy.equals("rename_incoming")) {
            return new OperationResult(false, "conflict_policy must be fail, keep_existing, or rename_incoming");
        }

        String oldPath = symbolPath(symbol);
        String requestedName = trimToNull(newName);
        String targetName = requestedName == null ? symbol.getName() : requestedName;
        Symbol collision = findChildSymbol(program, targetNamespace, targetName);
        if (collision != null && collision.getID() != symbol.getID()) {
            if (policy.equals("keep_existing")) {
                return new OperationResult(true,
                    "status=skipped\nmoved=false\nold_path=" + oldPath
                        + "\nnew_path=" + symbolPath(collision)
                        + "\ncollision=" + safeValueForResponse(symbolPath(collision)));
            }
            if (policy.equals("fail")) {
                return new OperationResult(false,
                    "status=collision\nmoved=false\nold_path=" + oldPath
                        + "\nrequested_path=" + namespacePath(targetNamespace) + Namespace.DELIMITER + targetName
                        + "\ncollision=" + safeValueForResponse(symbolPath(collision)));
            }
            targetName = makeUniqueChildName(program, targetNamespace, targetName);
        }

        String newPath = namespacePath(targetNamespace) + Namespace.DELIMITER + targetName;
        if (dryRun) {
            return new OperationResult(true,
                "status=dry_run\nmoved=false\nold_path=" + oldPath + "\nnew_path=" + newPath);
        }

        try {
            symbol.setNameAndNamespace(targetName, targetNamespace, SourceType.USER_DEFINED);
            return new OperationResult(true,
                "status=ok\nmoved=true\nold_path=" + oldPath + "\nnew_path=" + symbolPath(symbol));
        } catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
            return new OperationResult(false, "Failed to move symbol: " + e.getMessage());
        }
    }

    private String setFunctionClass(String functionAddress, String classPath, String methodName,
                                    String thisParamName, String callingConvention, boolean dryRun,
                                    Map<String, String> params) {
        ProgramTargetContext context = resolveWriteTargetContext(params);
        if (context.hasError()) {
            return context.errorMessage;
        }

        AtomicReference<OperationResult> resultRef = new AtomicReference<>(new OperationResult(false, "set_function_class failed"));
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = context.program.startTransaction("Set function class");
                boolean commit = false;
                try {
                    OperationResult result = setFunctionClassInProgram(
                        context.program, functionAddress, classPath, methodName, thisParamName, callingConvention, dryRun);
                    resultRef.set(result);
                    commit = result.success && !dryRun;
                } finally {
                    context.program.endTransaction(tx, commit);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultRef.set(new OperationResult(false, "Failed to set function class on Swing thread: " + e.getMessage()));
        }

        try {
            String response = formatTargetedResponse(context, resultRef.get().message);
            if (resultRef.get().success && context.explicitTarget && !dryRun) {
                response = response + "\n" + saveExplicitTargetIfNeeded(context);
            }
            return response;
        } finally {
            closeWriteTargetContext(context);
        }
    }

    private OperationResult setFunctionClassInProgram(Program program, String functionAddress,
                                                      String classPath, String methodName,
                                                      String thisParamName, String callingConvention,
                                                      boolean dryRun) {
        Address addr = parseAddress(program, functionAddress);
        Function function = getFunctionForAddress(program, addr);
        if (function == null) {
            return new OperationResult(false, "function_address did not resolve to a function");
        }

        String before = function.getPrototypeString(true, true);
        OperationResult moveResult = moveSymbolToNamespaceInProgram(
            program,
            functionAddress,
            "",
            classPath,
            trimToNull(methodName),
            "rename_incoming",
            dryRun);
        if (!moveResult.success) {
            return moveResult;
        }

        List<String> lines = new ArrayList<>();
        lines.add(moveResult.message);

        String normalizedCallingConvention = trimToNull(callingConvention);
        if (normalizedCallingConvention != null) {
            if (dryRun) {
                lines.add("calling_convention_after=" + normalizeWhitespace(normalizedCallingConvention));
            } else {
                try {
                    function.setCallingConvention(normalizeLegacyCallingConventions(normalizedCallingConvention, true));
                } catch (InvalidInputException firstError) {
                    try {
                        function.setCallingConvention(normalizeLegacyCallingConventions(normalizedCallingConvention, false));
                    } catch (InvalidInputException secondError) {
                        return new OperationResult(false, "Failed to set calling convention: " + secondError.getMessage());
                    }
                }
            }
        }

        lines.add("function_address=" + function.getEntryPoint());
        lines.add("signature_before=" + before);
        lines.add("signature_after=" + function.getPrototypeString(true, true));
        if (trimToNull(thisParamName) != null) {
            lines.add("this_param_name=" + trimToNull(thisParamName));
        }
        return new OperationResult(true, String.join("\n", lines));
    }

    private String setFunctionThisType(String functionAddress, String thisType,
                                       String thisParamName, String thisStorage,
                                       String callingConvention, boolean dryRun,
                                       Map<String, String> params) {
        ProgramTargetContext context = resolveWriteTargetContext(params);
        if (context.hasError()) {
            return context.errorMessage;
        }

        AtomicReference<OperationResult> resultRef = new AtomicReference<>(new OperationResult(false, "set_function_this_type failed"));
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = context.program.startTransaction("Set function this type");
                boolean commit = false;
                try {
                    OperationResult result = setFunctionThisTypeInProgram(
                        context.program, functionAddress, thisType, thisParamName, thisStorage, callingConvention, dryRun);
                    resultRef.set(result);
                    commit = result.success && !dryRun;
                } finally {
                    context.program.endTransaction(tx, commit);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultRef.set(new OperationResult(false, "Failed to set this type on Swing thread: " + e.getMessage()));
        }

        try {
            String response = formatTargetedResponse(context, resultRef.get().message);
            if (resultRef.get().success && context.explicitTarget && !dryRun) {
                response = response + "\n" + saveExplicitTargetIfNeeded(context);
            }
            return response;
        } finally {
            closeWriteTargetContext(context);
        }
    }

    private OperationResult setFunctionThisTypeInProgram(Program program, String functionAddress,
                                                         String thisType, String thisParamName,
                                                         String thisStorage, String callingConvention,
                                                         boolean dryRun) {
        Address addr = parseAddress(program, functionAddress);
        Function function = getFunctionForAddress(program, addr);
        if (function == null) {
            return new OperationResult(false, "function_address did not resolve to a function");
        }

        String normalizedThisType = trimToNull(thisType);
        if (normalizedThisType == null) {
            return new OperationResult(false, "this_type is required");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType resolvedThisType = resolveDataType(dtm, normalizedThisType);
        if (resolvedThisType == null) {
            return new OperationResult(false, "Unable to resolve this_type: " + normalizedThisType);
        }

        String requestedParamName = trimToNull(thisParamName);
        if (requestedParamName == null) {
            requestedParamName = Function.THIS_PARAM_NAME;
        }

        String before = function.getPrototypeString(true, true);
        String storageHint = trimToNull(thisStorage);
        String normalizedStorageHint = storageHint == null ? "" : storageHint.toLowerCase(Locale.ROOT);
        boolean preserveExistingStorage = normalizedStorageHint.isBlank()
            || normalizedStorageHint.equals("preserve")
            || normalizedStorageHint.equals("existing")
            || normalizedStorageHint.equals("current");
        if (dryRun) {
            return new OperationResult(true,
                "status=dry_run\nfunction_address=" + function.getEntryPoint()
                    + "\nthis_type=" + resolvedThisType.getPathName()
                    + "\nthis_param_name=" + requestedParamName
                    + "\nthis_storage=" + safeValueForResponse(storageHint)
                    + "\nstorage_strategy=" + (preserveExistingStorage ? "custom_then_dynamic_fallback" : "dynamic_storage_override")
                    + "\nsignature_before=" + before
                    + "\nsignature_after=<pending update>");
        }

        try {
            Parameter[] parameters = function.getParameters();
            String storageStrategy = parameters.length == 0
                ? "dynamic_storage_new_parameter"
                : (preserveExistingStorage ? "preserved_custom_storage" : "dynamic_storage_override");
            List<String> warnings = new ArrayList<>();
            boolean applied = false;

            if (parameters.length > 0 && preserveExistingStorage) {
                List<Variable> customReplacements = new ArrayList<>();
                Parameter first = parameters[0];
                customReplacements.add(new ParameterImpl(
                    requestedParamName,
                    resolvedThisType,
                    first.getVariableStorage(),
                    program,
                    SourceType.USER_DEFINED));
                for (int index = 1; index < parameters.length; index++) {
                    customReplacements.add(new ParameterImpl(parameters[index], program));
                }
                try {
                    function.replaceParameters(customReplacements,
                        Function.FunctionUpdateType.CUSTOM_STORAGE,
                        true,
                        SourceType.USER_DEFINED);
                    applied = true;
                } catch (InvalidInputException customStorageError) {
                    storageStrategy = "dynamic_storage_fallback";
                    warnings.add("warning=this_storage_fallback\treason="
                        + safeValueForResponse(normalizeWhitespace(customStorageError.getMessage())));
                }
            }

            if (!applied) {
                List<Variable> replacements = new ArrayList<>();
                replacements.add(new ParameterImpl(
                    requestedParamName,
                    resolvedThisType,
                    program,
                    SourceType.USER_DEFINED));
                for (int index = 1; index < parameters.length; index++) {
                    replacements.add(new ParameterImpl(parameters[index], program));
                }
                function.replaceParameters(replacements,
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true,
                    SourceType.USER_DEFINED);
            }

            String normalizedCallingConvention = trimToNull(callingConvention);
            if (normalizedCallingConvention != null) {
                try {
                    function.setCallingConvention(normalizeLegacyCallingConventions(normalizedCallingConvention, true));
                } catch (InvalidInputException firstError) {
                    function.setCallingConvention(normalizeLegacyCallingConventions(normalizedCallingConvention, false));
                }
            }

            return new OperationResult(true,
                "status=ok\nfunction_address=" + function.getEntryPoint()
                    + "\nthis_type=" + resolvedThisType.getPathName()
                    + "\nthis_param_name=" + requestedParamName
                    + "\nthis_storage=" + safeValueForResponse(storageHint)
                    + "\nstorage_strategy=" + storageStrategy
                    + "\nsignature_before=" + before
                    + "\nsignature_after=" + function.getPrototypeString(true, true)
                    + (warnings.isEmpty() ? "" : "\n" + String.join("\n", warnings)));
        } catch (DuplicateNameException | InvalidInputException e) {
            return new OperationResult(false, "Failed to apply this type: " + e.getMessage());
        }
    }

    private String createOrUpdateStruct(String name, String categoryPath, int size, int packing,
                                        String fields, boolean dryRun, Map<String, String> params) {
        ProgramTargetContext context = resolveWriteTargetContext(params);
        if (context.hasError()) {
            return context.errorMessage;
        }

        AtomicReference<OperationResult> resultRef = new AtomicReference<>(new OperationResult(false, "create_or_update_struct failed"));
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = context.program.startTransaction("Create or update struct");
                boolean commit = false;
                try {
                    OperationResult result = createOrUpdateStructInProgram(context.program, name, categoryPath, size, packing, fields, dryRun);
                    resultRef.set(result);
                    commit = result.success && !dryRun;
                } finally {
                    context.program.endTransaction(tx, commit);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultRef.set(new OperationResult(false, "Failed to create/update struct on Swing thread: " + e.getMessage()));
        }

        try {
            String response = formatTargetedResponse(context, resultRef.get().message);
            if (resultRef.get().success && context.explicitTarget && !dryRun) {
                response = response + "\n" + saveExplicitTargetIfNeeded(context);
            }
            return response;
        } finally {
            closeWriteTargetContext(context);
        }
    }

    private OperationResult createOrUpdateStructInProgram(Program program, String name,
                                                          String categoryPath, int size, int packing,
                                                          String fields, boolean dryRun) {
        String normalizedName = trimToNull(name);
        if (normalizedName == null) {
            return new OperationResult(false, "name is required");
        }
        if (fields == null || fields.isBlank()) {
            return new OperationResult(false, "fields is required");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath normalizedCategoryPath = normalizeCategoryPath(categoryPath);
        StructureDataType structure = new StructureDataType(normalizedCategoryPath, normalizedName, Math.max(size, 0), dtm);
        List<String> fieldLines = new ArrayList<>();
        int fieldCount = 0;
        int requiredLength = Math.max(size, 0);

        for (String rawLine : fields.split("\\r?\\n")) {
            if (rawLine.isBlank()) {
                continue;
            }
            String[] parts = rawLine.split("\\t", -1);
            if (parts.length < 3) {
                return new OperationResult(false, "Invalid field line: " + rawLine);
            }

            int offset = parseIntOrDefault(parts[0].trim(), -1);
            if (offset < 0) {
                return new OperationResult(false, "Invalid field offset: " + parts[0]);
            }
            String fieldName = trimToNull(parts[1]);
            String datatypeName = trimToNull(parts[2]);
            if (fieldName == null || datatypeName == null) {
                return new OperationResult(false, "Field name and datatype are required: " + rawLine);
            }

            DataType fieldType = resolveDataType(dtm, datatypeName);
            if (fieldType == null) {
                return new OperationResult(false, "Unable to resolve field datatype: " + datatypeName);
            }

            String comment = parts.length >= 4 ? trimToNull(parts[3]) : null;
            String confidence = parts.length >= 5 ? trimToNull(parts[4]) : null;
            if (confidence != null) {
                comment = comment == null ? "confidence=" + confidence : comment + " | confidence=" + confidence;
            }

            int componentLength = Math.max(fieldType.getLength(), 1);
            int endOffset = offset + componentLength;
            if (endOffset > requiredLength) {
                requiredLength = endOffset;
            }
            if (endOffset > structure.getLength()) {
                structure.growStructure(endOffset - structure.getLength());
            }
            structure.replaceAtOffset(offset, fieldType, componentLength, fieldName, comment);
            fieldLines.add("field_offset=" + offset + "\tname=" + fieldName + "\tdatatype=" + fieldType.getPathName());
            fieldCount++;
        }

        if (requiredLength > structure.getLength()) {
            structure.setLength(requiredLength);
        }

        String datatypePath = normalizedCategoryPath.getPath() + "/" + normalizedName;
        if (dryRun) {
            return new OperationResult(true,
                "status=dry_run\ndatatype_path=" + datatypePath
                    + "\ncreated_or_updated=false\nsize=" + structure.getLength()
                    + "\nfield_count=" + fieldCount
                    + (packing > 0 ? "\npacking_ignored=" + packing : "")
                    + (fieldLines.isEmpty() ? "" : "\n" + String.join("\n", fieldLines)));
        }

        dtm.createCategory(normalizedCategoryPath);
        DataType resolved = dtm.addDataType(structure, DataTypeConflictHandler.REPLACE_HANDLER);
        return new OperationResult(true,
            "status=ok\ndatatype_path=" + resolved.getPathName()
                + "\ncreated_or_updated=true\nsize=" + structure.getLength()
                + "\nfield_count=" + fieldCount
                + (packing > 0 ? "\npacking_ignored=" + packing : "")
                + (fieldLines.isEmpty() ? "" : "\n" + String.join("\n", fieldLines)));
    }

    private String createOrUpdateVtable(String name, String categoryPath, String slots,
                                        boolean dryRun, Map<String, String> params) {
        ProgramTargetContext context = resolveWriteTargetContext(params);
        if (context.hasError()) {
            return context.errorMessage;
        }

        AtomicReference<OperationResult> resultRef = new AtomicReference<>(new OperationResult(false, "create_or_update_vtable failed"));
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = context.program.startTransaction("Create or update vtable");
                boolean commit = false;
                try {
                    OperationResult result = createOrUpdateVtableInProgram(context.program, name, categoryPath, slots, dryRun);
                    resultRef.set(result);
                    commit = result.success && !dryRun;
                } finally {
                    context.program.endTransaction(tx, commit);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultRef.set(new OperationResult(false, "Failed to create/update vtable on Swing thread: " + e.getMessage()));
        }

        try {
            String response = formatTargetedResponse(context, resultRef.get().message);
            if (resultRef.get().success && context.explicitTarget && !dryRun) {
                response = response + "\n" + saveExplicitTargetIfNeeded(context);
            }
            return response;
        } finally {
            closeWriteTargetContext(context);
        }
    }

    private OperationResult createOrUpdateVtableInProgram(Program program, String name,
                                                          String categoryPath, String slots,
                                                          boolean dryRun) {
        String normalizedName = trimToNull(name);
        if (normalizedName == null) {
            return new OperationResult(false, "name is required");
        }
        if (slots == null || slots.isBlank()) {
            return new OperationResult(false, "slots is required");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath normalizedCategoryPath = normalizeCategoryPath(categoryPath);
        StructureDataType vtable = new StructureDataType(normalizedCategoryPath, normalizedName, 0, dtm);
        List<String> boundFunctions = new ArrayList<>();
        int pointerSize = Math.max(program.getDefaultPointerSize(), 1);
        int requiredLength = 0;
        int slotCount = 0;

        for (String rawLine : slots.split("\\r?\\n")) {
            if (rawLine.isBlank()) {
                continue;
            }
            String[] parts = rawLine.split("\\t", -1);
            if (parts.length < 2) {
                return new OperationResult(false, "Invalid slot line: " + rawLine);
            }

            int offset = parseIntOrDefault(parts[0].trim(), -1);
            if (offset < 0) {
                return new OperationResult(false, "Invalid slot offset: " + parts[0]);
            }

            String slotName = trimToNull(parts[1]);
            if (slotName == null) {
                slotName = String.format(Locale.ROOT, "slot_%04x", offset);
            }
            String functionAddress = parts.length >= 3 ? trimToNull(parts[2]) : null;
            String prototype = parts.length >= 4 ? trimToNull(parts[3]) : null;
            String comment = parts.length >= 5 ? trimToNull(parts[4]) : null;

            DataType slotType = buildVtableSlotPointerType(program, normalizedCategoryPath, slotName, functionAddress, prototype);
            if (slotType == null) {
                slotType = dtm.getPointer(new Undefined1DataType());
            }

            int componentLength = Math.max(pointerSize, Math.max(slotType.getLength(), 1));
            int endOffset = offset + componentLength;
            if (endOffset > requiredLength) {
                requiredLength = endOffset;
            }
            if (endOffset > vtable.getLength()) {
                vtable.growStructure(endOffset - vtable.getLength());
            }
            vtable.replaceAtOffset(offset, slotType, componentLength, slotName, comment);

            String boundFunctionName = "";
            if (functionAddress != null) {
                Function function = resolveFunctionIdentifier(program, functionAddress);
                if (function != null) {
                    boundFunctionName = function.getName();
                }
            }
            boundFunctions.add("offset=" + offset
                + "\tfunction_address=" + safeValueForResponse(functionAddress)
                + "\tname=" + safeValueForResponse(boundFunctionName));
            slotCount++;
        }

        if (requiredLength > vtable.getLength()) {
            vtable.setLength(requiredLength);
        }

        String datatypePath = normalizedCategoryPath.getPath() + "/" + normalizedName;
        if (dryRun) {
            return new OperationResult(true,
                "status=dry_run\ndatatype_path=" + datatypePath
                    + "\nslot_count=" + slotCount
                    + (boundFunctions.isEmpty() ? "" : "\n" + String.join("\n", boundFunctions)));
        }

        dtm.createCategory(normalizedCategoryPath);
        DataType resolved = dtm.addDataType(vtable, DataTypeConflictHandler.REPLACE_HANDLER);
        return new OperationResult(true,
            "status=ok\ndatatype_path=" + resolved.getPathName()
                + "\nslot_count=" + slotCount
                + (boundFunctions.isEmpty() ? "" : "\n" + String.join("\n", boundFunctions)));
    }

    private String analyzeVtable(Program program, String address, int slotCount, boolean stopOnInvalidPointer) {
        Address start = parseAddress(program, address);
        if (start == null) {
            return "address is required";
        }

        int resolvedSlotCount = slotCount > 0 ? slotCount : 16;
        int pointerSize = Math.max(program.getDefaultPointerSize(), 1);
        List<String> lines = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        for (int index = 0; index < resolvedSlotCount; index++) {
            int offset = index * pointerSize;
            Address entryAddress = start.add(offset);
            Address targetAddress = resolveVtableEntryTarget(program, entryAddress, pointerSize);
            if (targetAddress == null) {
                warnings.add("warning=invalid_pointer\tentry_address=" + entryAddress + "\toffset=" + offset);
                if (stopOnInvalidPointer) {
                    break;
                }
                continue;
            }

            Function function = getFunctionForAddress(program, targetAddress);
            Symbol symbol = program.getSymbolTable().getPrimarySymbol(targetAddress);
            String targetName = symbol != null ? symbol.getName() : safeFunctionName(function);
            String owner = "";
            if (function != null) {
                owner = namespacePath(function.getParentNamespace());
            } else if (symbol != null && symbol.getParentNamespace() != null) {
                owner = namespacePath(symbol.getParentNamespace());
            }

            lines.add("slot_offset=" + offset
                + "\tentry_address=" + entryAddress
                + "\ttarget_address=" + targetAddress
                + "\ttarget_name=" + safeValueForResponse(targetName)
                + "\tis_function=" + (function != null)
                + "\tcurrent_owner=" + safeValueForResponse(owner));
        }

        StringBuilder out = new StringBuilder();
        out.append("status=ok\naddress=").append(start)
            .append("\nslot_count=").append(lines.size())
            .append("\npointer_size=").append(pointerSize);
        if (!lines.isEmpty()) {
            out.append("\n").append(String.join("\n", lines));
        }
        if (!warnings.isEmpty()) {
            out.append("\n").append(String.join("\n", warnings));
        }
        return out.toString();
    }

    private String applyClassLayout(String classPath, String instanceStruct, String vtableStruct,
                                    String vtableAddress, String methods, boolean dryRun,
                                    Map<String, String> params) {
        ProgramTargetContext context = resolveWriteTargetContext(params);
        if (context.hasError()) {
            return context.errorMessage;
        }

        AtomicReference<OperationResult> resultRef = new AtomicReference<>(new OperationResult(false, "apply_class_layout failed"));
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = context.program.startTransaction("Apply class layout");
                boolean commit = false;
                try {
                    OperationResult result = applyClassLayoutInProgram(
                        context.program, classPath, instanceStruct, vtableStruct, vtableAddress, methods, dryRun);
                    resultRef.set(result);
                    commit = result.success && !dryRun;
                } finally {
                    context.program.endTransaction(tx, commit);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultRef.set(new OperationResult(false, "Failed to apply class layout on Swing thread: " + e.getMessage()));
        }

        try {
            String response = formatTargetedResponse(context, resultRef.get().message);
            if (resultRef.get().success && context.explicitTarget && !dryRun) {
                response = response + "\n" + saveExplicitTargetIfNeeded(context);
            }
            return response;
        } finally {
            closeWriteTargetContext(context);
        }
    }

    private OperationResult applyClassLayoutInProgram(Program program, String classPath,
                                                      String instanceStruct, String vtableStruct,
                                                      String vtableAddress, String methods,
                                                      boolean dryRun) {
        String normalizedClassPath = trimToNull(classPath);
        String normalizedInstanceStruct = trimToNull(instanceStruct);
        if (normalizedClassPath == null) {
            return new OperationResult(false, "class_path is required");
        }
        if (normalizedInstanceStruct == null) {
            return new OperationResult(false, "instance_struct is required");
        }
        if (methods == null || methods.isBlank()) {
            return new OperationResult(false, "methods is required");
        }

        DataType instanceType = resolveDataType(program.getDataTypeManager(), normalizedInstanceStruct);
        if (instanceType == null) {
            return new OperationResult(false, "Unable to resolve instance_struct: " + normalizedInstanceStruct);
        }

        DataType resolvedVtableType = null;
        String normalizedVtableStruct = trimToNull(vtableStruct);
        if (normalizedVtableStruct != null) {
            resolvedVtableType = resolveDataType(program.getDataTypeManager(), normalizedVtableStruct);
            if (resolvedVtableType == null) {
                return new OperationResult(false, "Unable to resolve vtable_struct: " + normalizedVtableStruct);
            }
        }

        NamespaceResolutionResult classNamespaceResult = resolveNamespacePath(program, normalizedClassPath, true, true);
        if (classNamespaceResult.hasError()) {
            return new OperationResult(false, classNamespaceResult.errorMessage);
        }

        List<String> warnings = new ArrayList<>();
        List<String> applied = new ArrayList<>();
        int appliedMethods = 0;
        int typedMethods = 0;
        int typingFailures = 0;
        String defaultThisType = instanceType.getPathName().endsWith("*")
            ? instanceType.getPathName()
            : instanceType.getPathName() + " *";

        for (String rawLine : methods.split("\\r?\\n")) {
            if (rawLine.isBlank()) {
                continue;
            }
            String[] parts = rawLine.split("\\t", -1);
            if (parts.length < 2) {
                return new OperationResult(false, "Invalid method line: " + rawLine);
            }

            String functionAddress = trimToNull(parts[0]);
            String methodName = trimToNull(parts[1]);
            String slotOffset = parts.length >= 3 ? trimToNull(parts[2]) : null;
            boolean isVirtual = parts.length >= 4 && parseBooleanOrDefault(parts[3], false);
            String methodThisType = parts.length >= 5 ? trimToNull(parts[4]) : null;
            String comment = parts.length >= 6 ? trimToNull(parts[5]) : null;
            String methodThisStorage = parts.length >= 7 ? trimToNull(parts[6]) : null;
            String methodCallingConvention = parts.length >= 8 ? trimToNull(parts[7]) : null;

            OperationResult moveResult = moveSymbolToNamespaceInProgram(
                program, functionAddress, "", normalizedClassPath, methodName, "rename_incoming", dryRun);
            if (!moveResult.success) {
                return moveResult;
            }

            OperationResult thisTypeResult = setFunctionThisTypeInProgram(
                program,
                functionAddress,
                methodThisType == null ? defaultThisType : methodThisType,
                Function.THIS_PARAM_NAME,
                methodThisStorage == null ? "farptr" : methodThisStorage,
                methodCallingConvention == null ? "" : methodCallingConvention,
                dryRun);

            Address addr = parseAddress(program, functionAddress);
            Function function = getFunctionForAddress(program, addr);
            if (function != null && comment != null && !dryRun) {
                function.setComment(comment);
            }
            boolean typingApplied = thisTypeResult.success;
            if (!typingApplied) {
                typingFailures++;
                warnings.add("warning=this_type_apply_failed\tfunction_address="
                    + safeValueForResponse(functionAddress)
                    + "\treason=" + safeValueForResponse(normalizeWhitespace(thisTypeResult.message)));
            } else {
                typedMethods++;
            }
            if (isVirtual && slotOffset == null) {
                warnings.add("warning=virtual_method_missing_slot\tfunction_address=" + safeValueForResponse(functionAddress));
            }
            if (isVirtual && normalizedVtableStruct == null) {
                warnings.add("warning=virtual_method_without_vtable_struct\tfunction_address=" + safeValueForResponse(functionAddress));
            }

            applied.add("function_address=" + safeValueForResponse(functionAddress)
                + "\tmethod_name=" + safeValueForResponse(methodName)
                + "\tis_virtual=" + isVirtual
                + "\tthis_type_applied=" + typingApplied
                + "\tslot_offset=" + safeValueForResponse(slotOffset));
            appliedMethods++;
        }

        if (trimToNull(vtableAddress) != null && normalizedVtableStruct != null) {
            warnings.add("warning=vtable_binding_not_materialized\tvtable_address=" + trimToNull(vtableAddress)
                + "\tvtable_struct=" + normalizedVtableStruct);
        }

        StringBuilder out = new StringBuilder();
        out.append("status=").append(dryRun ? "dry_run" : "ok")
            .append("\nclass_path=").append(namespacePath(classNamespaceResult.namespace))
            .append("\ninstance_struct=").append(instanceType.getPathName())
            .append("\napplied_methods=").append(appliedMethods)
            .append("\ntyped_methods=").append(typedMethods)
            .append("\ntyping_failures=").append(typingFailures)
            .append("\napplied_structs=").append(1 + (resolvedVtableType != null ? 1 : 0));
        if (resolvedVtableType != null) {
            out.append("\nvtable_struct=").append(resolvedVtableType.getPathName());
        }
        if (!applied.isEmpty()) {
            out.append("\n").append(String.join("\n", applied));
        }
        if (!warnings.isEmpty()) {
            out.append("\n").append(String.join("\n", warnings));
        }
        return new OperationResult(true, out.toString());
    }

    private NamespaceResolutionResult resolveNamespacePath(Program program, String path,
                                                           boolean createMissing, boolean leafIsClass) {
        Namespace current = program.getGlobalNamespace();
        String normalizedPath = trimToNull(path);
        if (normalizedPath == null) {
            return new NamespaceResolutionResult(current, null);
        }

        String[] parts = splitNamespacePath(normalizedPath);
        SymbolTable symbolTable = program.getSymbolTable();
        for (int index = 0; index < parts.length; index++) {
            String part = trimToNull(parts[index]);
            if (part == null) {
                continue;
            }
            boolean isLeaf = index == parts.length - 1;
            Namespace next = findChildNamespace(symbolTable, current, part);
            if (next == null && createMissing) {
                try {
                    next = isLeaf && leafIsClass
                        ? symbolTable.createClass(current, part, SourceType.USER_DEFINED)
                        : symbolTable.createNameSpace(current, part, SourceType.USER_DEFINED);
                } catch (DuplicateNameException | InvalidInputException e) {
                    return new NamespaceResolutionResult(null, "Failed to create namespace path: " + e.getMessage());
                }
            }
            if (next == null) {
                return new NamespaceResolutionResult(null,
                    "Namespace not found: " + normalizedPath);
            }
            current = next;
        }
        return new NamespaceResolutionResult(current, null);
    }

    private Namespace findChildNamespace(SymbolTable symbolTable, Namespace parent, String name) {
        Namespace namespace = symbolTable.getNamespace(name, parent);
        if (namespace != null) {
            return namespace;
        }
        Symbol classSymbol = symbolTable.getClassSymbol(name, parent);
        if (classSymbol != null && classSymbol.getObject() instanceof Namespace) {
            return (Namespace) classSymbol.getObject();
        }
        return null;
    }

    private SymbolLookupResult resolveMovableSymbol(Program program, String symbolAddress, String symbolName) {
        Address addr = parseAddress(program, symbolAddress);
        if (addr != null) {
            Function function = getFunctionForAddress(program, addr);
            if (function != null) {
                return new SymbolLookupResult(function.getSymbol(), null);
            }
            Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
            if (symbol != null) {
                return new SymbolLookupResult(symbol, null);
            }
            return new SymbolLookupResult(null, "No symbol found at symbol_address");
        }

        String normalizedName = trimToNull(symbolName);
        if (normalizedName == null) {
            return new SymbolLookupResult(null, "symbol_address or symbol_name is required");
        }

        SymbolIterator iterator = program.getSymbolTable().scanSymbolsByName(normalizedName);
        Symbol match = null;
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            if (symbol == null || symbol.isDynamic()) {
                continue;
            }
            if (match != null && match.getID() != symbol.getID()) {
                return new SymbolLookupResult(null, "symbol_name is ambiguous; use symbol_address instead");
            }
            match = symbol;
        }

        if (match == null) {
            return new SymbolLookupResult(null, "No symbol found for symbol_name");
        }
        return new SymbolLookupResult(match, null);
    }

    private Symbol findChildSymbol(Program program, Namespace namespace, String name) {
        List<Symbol> symbols = program.getSymbolTable().getSymbols(name, namespace);
        for (Symbol symbol : symbols) {
            if (symbol != null && !symbol.isDeleted()) {
                return symbol;
            }
        }
        Symbol classSymbol = program.getSymbolTable().getClassSymbol(name, namespace);
        if (classSymbol != null && !classSymbol.isDeleted()) {
            return classSymbol;
        }
        return null;
    }

    private String makeUniqueChildName(Program program, Namespace namespace, String baseName) {
        String candidate = baseName;
        int suffix = 1;
        while (findChildSymbol(program, namespace, candidate) != null) {
            candidate = baseName + "_" + suffix;
            suffix++;
        }
        return candidate;
    }

    private String[] splitNamespacePath(String path) {
        String normalized = path.replace('\\', '/');
        normalized = normalized.replace("::", "/");
        normalized = normalized.replaceAll("/+", "/");
        if (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        if (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized.isBlank() ? new String[0] : normalized.split("/");
    }

    private String namespacePath(Namespace namespace) {
        if (namespace == null || namespace.isGlobal()) {
            return "<global>";
        }
        return String.join(Namespace.DELIMITER, namespace.getPathList(true));
    }

    private String namespaceKind(Namespace namespace) {
        if (namespace instanceof GhidraClass || namespace.getType() == Namespace.Type.CLASS) {
            return "class";
        }
        return "namespace";
    }

    private String symbolPath(Symbol symbol) {
        if (symbol == null) {
            return "";
        }
        return String.join(Namespace.DELIMITER, symbol.getPath());
    }

    private CategoryPath normalizeCategoryPath(String categoryPath) {
        String normalized = trimToNull(categoryPath);
        if (normalized == null || normalized.equals("/")) {
            return CategoryPath.ROOT;
        }
        normalized = normalized.replace('\\', '/');
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        return new CategoryPath(normalized);
    }

    private DataType buildVtableSlotPointerType(Program program, CategoryPath categoryPath,
                                                String slotName, String functionAddress,
                                                String prototype) {
        DataTypeManager dtm = program.getDataTypeManager();

        if (functionAddress != null) {
            Function function = resolveFunctionIdentifier(program, functionAddress);
            if (function != null) {
                FunctionDefinitionDataType definition = new FunctionDefinitionDataType(categoryPath, slotName + "Fn", function.getSignature(), dtm);
                DataType resolved = dtm.resolve(definition, DataTypeConflictHandler.REPLACE_HANDLER);
                return dtm.getPointer(resolved);
            }
        }

        if (prototype != null) {
            FunctionDefinitionDataType definition = parseFunctionDefinition(program, categoryPath, slotName + "Fn", prototype);
            if (definition != null) {
                DataType resolved = dtm.resolve(definition, DataTypeConflictHandler.REPLACE_HANDLER);
                return dtm.getPointer(resolved);
            }
        }

        return dtm.getPointer(new Undefined1DataType());
    }

    private FunctionDefinitionDataType parseFunctionDefinition(Program program, CategoryPath categoryPath,
                                                               String name, String prototype) {
        DataTypeManager dtm = program.getDataTypeManager();
        ghidra.app.services.DataTypeManagerService dtms =
            tool.getService(ghidra.app.services.DataTypeManagerService.class);
        ghidra.app.util.parser.FunctionSignatureParser parser =
            new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

        for (String candidate : buildPrototypeCandidates(prototype)) {
            try {
                return new FunctionDefinitionDataType(categoryPath, name, parser.parse(null, candidate), dtm);
            } catch (Exception ignored) {
                // Try the next normalized candidate.
            }
        }
        return null;
    }

    private Address resolveVtableEntryTarget(Program program, Address entryAddress, int pointerSize) {
        try {
            Reference[] refs = program.getReferenceManager().getReferencesFrom(entryAddress);
            if (refs != null) {
                for (Reference ref : refs) {
                    if (ref != null && ref.getToAddress() != null) {
                        return ref.getToAddress();
                    }
                }
            }

            byte[] data = new byte[pointerSize];
            int read = program.getMemory().getBytes(entryAddress, data);
            if (read != pointerSize) {
                return null;
            }

            if (pointerSize == 4) {
                int offset = (data[0] & 0xff) | ((data[1] & 0xff) << 8);
                int segment = (data[2] & 0xff) | ((data[3] & 0xff) << 8);
                Address segmentedAddress = parseAddress(program,
                    String.format(Locale.ROOT, "%04x:%04x", segment, offset));
                if (segmentedAddress != null) {
                    return segmentedAddress;
                }
            }

            long flatValue = 0;
            for (int index = 0; index < pointerSize; index++) {
                flatValue |= (long) (data[index] & 0xff) << (index * 8);
            }
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(flatValue);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        return setCommentAtAddress(program, addressStr, comment, commentType, transactionName);
    }

    private boolean setCommentAtAddress(Program program, String addressStr, String comment,
                                        int commentType, String transactionName) {
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

    private boolean setDecompilerComment(Program program, String addressStr, String comment) {
        return setCommentAtAddress(program, addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    private boolean setDisassemblyComment(Program program, String addressStr, String comment) {
        return setCommentAtAddress(program, addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
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
        return renameFunctionByAddress(program, functionAddrStr, newName);
    }

    private boolean renameFunctionByAddress(Program program, String functionAddrStr, String newName) {
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
        return getXrefsTo(getCurrentProgram(), addressStr, offset, limit);
    }

    private String getXrefsTo(Program program, String addressStr, int offset, int limit) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = parseAddress(program, addressStr);
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
        return getXrefsFrom(getCurrentProgram(), addressStr, offset, limit);
    }

    private String getXrefsFrom(Program program, String addressStr, int offset, int limit) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = parseAddress(program, addressStr);
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
        return getFunctionXrefs(getCurrentProgram(), functionName, offset, limit);
    }

    private String getFunctionXrefs(Program program, String functionName, int offset, int limit) {
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            int pageSize = Math.max(1, limit);
            int fetchLimit = Math.max(pageSize, Math.min(Math.max(0, offset) + pageSize, 1000));
            String callers = getCallers(program, functionName, true, true, true, fetchLimit);
            List<String> lines = new ArrayList<>();
            for (String line : callers.split("\\r?\\n")) {
                if (line.startsWith("from=")) {
                    lines.add(line);
                }
            }
            if (lines.isEmpty()) {
                return callers;
            }
            return paginateList(lines, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        return listDefinedStrings(getCurrentProgram(), offset, limit, filter);
    }

    private String listDefinedStrings(Program program, int offset, int limit, String filter) {
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
        String normalizedTypeName = normalizeWhitespace(typeName);
        if (normalizedTypeName.isBlank()) {
            return null;
        }

        int pointerDepth = 0;
        while (normalizedTypeName.endsWith("*")) {
            pointerDepth++;
            normalizedTypeName = normalizeWhitespace(normalizedTypeName.substring(0, normalizedTypeName.length() - 1));
        }

        if (normalizedTypeName.regionMatches(true, 0, "struct ", 0, 7)) {
            normalizedTypeName = normalizedTypeName.substring(7).trim();
        }

        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, normalizedTypeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            for (int index = 0; index < pointerDepth; index++) {
                dataType = dtm.getPointer(dataType);
            }
            return dataType;
        }

        DataType pathType = dtm.getDataType(normalizedTypeName);
        if (pathType == null && !normalizedTypeName.startsWith("/")) {
            pathType = dtm.getDataType("/" + normalizedTypeName);
        }
        if (pathType != null) {
            for (int index = 0; index < pointerDepth; index++) {
                pathType = dtm.getPointer(pathType);
            }
            return pathType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (normalizedTypeName.startsWith("P") && normalizedTypeName.length() > 1) {
            String baseTypeName = normalizedTypeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                dataType = dtm.getPointer(dtm.getDataType("/void"));
                for (int index = 0; index < pointerDepth; index++) {
                    dataType = dtm.getPointer(dataType);
                }
                return dataType;
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                dataType = dtm.getPointer(baseType);
                for (int index = 0; index < pointerDepth; index++) {
                    dataType = dtm.getPointer(dataType);
                }
                return dataType;
            }

            Msg.warn(this, "Base type not found for " + normalizedTypeName + ", defaulting to void*");
            dataType = dtm.getPointer(dtm.getDataType("/void"));
            for (int index = 0; index < pointerDepth; index++) {
                dataType = dtm.getPointer(dataType);
            }
            return dataType;
        }

        // Handle common built-in types
        switch (normalizedTypeName.toLowerCase()) {
            case "int":
            case "long":
                dataType = dtm.getDataType("/int");
                break;
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                dataType = dtm.getDataType("/uint");
                break;
            case "short":
                dataType = dtm.getDataType("/short");
                break;
            case "ushort":
            case "unsigned short":
            case "word":
                dataType = dtm.getDataType("/ushort");
                break;
            case "char":
            case "byte":
                dataType = dtm.getDataType("/char");
                break;
            case "uchar":
            case "unsigned char":
                dataType = dtm.getDataType("/uchar");
                break;
            case "longlong":
            case "__int64":
                dataType = dtm.getDataType("/longlong");
                break;
            case "ulonglong":
            case "unsigned __int64":
                dataType = dtm.getDataType("/ulonglong");
                break;
            case "bool":
            case "boolean":
                dataType = dtm.getDataType("/bool");
                break;
            case "void":
                dataType = dtm.getDataType("/void");
                break;
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + normalizedTypeName);
                if (directType != null) {
                    dataType = directType;
                    break;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + normalizedTypeName + ", defaulting to int");
                dataType = dtm.getDataType("/int");
                break;
        }

        for (int index = 0; index < pointerDepth; index++) {
            dataType = dtm.getPointer(dataType);
        }
        return dataType;
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
        return createFunctionByAddress(program, entryStr, name, bodyStartStr, bodyEndStr, comment).message;
    }

    private OperationResult createFunctionByAddress(Program program, String entryStr, String name,
                                                    String bodyStartStr, String bodyEndStr,
                                                    String comment) {
        if (entryStr == null || bodyStartStr == null || bodyEndStr == null) {
            return new OperationResult(false, "entry, body_start and body_end are required");
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
            return new OperationResult(false, "Failed to create function on Swing thread: " + e.getMessage());
        }
        return new OperationResult(success.get(), message.toString());
    }

    private String deleteFunctionByAddress(String entryStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return deleteFunctionByAddress(program, entryStr).message;
    }

    private OperationResult deleteFunctionByAddress(Program program, String entryStr) {
        if (entryStr == null || entryStr.isBlank()) return new OperationResult(false, "entry is required");

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
            return new OperationResult(false, "Failed to delete function on Swing thread: " + e.getMessage());
        }
        return new OperationResult(success.get(), message.toString());
    }

    private String getFunctionContaining(String addressStr) {
        return getFunctionContaining(getCurrentProgram(), addressStr);
    }

    private String getFunctionContaining(Program program, String addressStr) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isBlank()) return "address is required";

        try {
            Address addr = parseAddress(program, addressStr);
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
        return readRegion(getCurrentProgram(), startStr, endStr);
    }

    private String readRegion(Program program, String startStr, String endStr) {
        if (program == null) return "No program loaded";
        if (startStr == null || endStr == null) return "start and end are required";

        try {
            Address start = parseAddress(program, startStr);
            Address end = parseAddress(program, endStr);
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
        return disassembleRegion(getCurrentProgram(), startStr, endStr);
    }

    private String disassembleRegion(Program program, String startStr, String endStr) {
        if (program == null) return "No program loaded";
        if (startStr == null || endStr == null) return "start and end are required";

        try {
            Address start = parseAddress(program, startStr);
            Address end = parseAddress(program, endStr);
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
        return getInstructionWindow(getCurrentProgram(), addressStr, beforeCount, afterCount);
    }

    private String getInstructionWindow(Program program, String addressStr, int beforeCount, int afterCount) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isBlank()) return "address is required";

        try {
            Listing listing = program.getListing();
            Address addr = parseAddress(program, addressStr);
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
        return searchInstructions(getCurrentProgram(), query, mode, limit);
    }

    private String searchInstructions(Program program, String query, String mode, int limit) {
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
        return getDataUses(getCurrentProgram(), addressStr, includeOperandScans, limit);
    }

    private String getDataUses(Program program, String addressStr, boolean includeOperandScans, int limit) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isBlank()) return "address is required";

        LinkedHashSet<String> uses = new LinkedHashSet<>();

        String xrefs = getXrefsTo(program, addressStr, 0, Math.max(1, limit));
        if (xrefs != null && !xrefs.isBlank()) {
            for (String line : xrefs.split("\\r?\\n")) {
                if (!line.isBlank()) {
                    uses.add("xref: " + line);
                }
            }
        }

        if (includeOperandScans && uses.size() < limit) {
            String scanned = searchInstructions(program, addressStr, "address", limit);
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

    private String searchBytes(Program program, String patternText, String startStr,
                               String endStr, String segmentFilter, int maxHits) {
        if (program == null) return "No program loaded";
        if (patternText == null || patternText.isBlank()) return "pattern is required";

        int[] pattern;
        try {
            pattern = parseBytePattern(patternText);
        } catch (IllegalArgumentException e) {
            return "Invalid pattern: " + e.getMessage();
        }

        Address requestedStart = startStr == null || startStr.isBlank() ? null : parseAddress(program, startStr);
        Address requestedEnd = endStr == null || endStr.isBlank() ? null : parseAddress(program, endStr);
        if ((startStr != null && !startStr.isBlank() && requestedStart == null) ||
            (endStr != null && !endStr.isBlank() && requestedEnd == null)) {
            return "Invalid start or end address";
        }
        if (requestedStart != null && requestedEnd != null && requestedEnd.compareTo(requestedStart) < 0) {
            return "end must be >= start";
        }

        int hitLimit = Math.max(1, Math.min(maxHits, 1000));
        String filter = trimToNull(segmentFilter);
        if (filter != null) {
            filter = filter.toLowerCase(Locale.ROOT);
        }

        List<String> hits = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (filter != null && !block.getName().toLowerCase(Locale.ROOT).contains(filter)) {
                continue;
            }

            Address searchStart = block.getStart();
            Address searchEnd = block.getEnd();
            if (requestedStart != null && searchStart.compareTo(requestedStart) < 0) {
                searchStart = requestedStart;
            }
            if (requestedEnd != null && searchEnd.compareTo(requestedEnd) > 0) {
                searchEnd = requestedEnd;
            }
            if (searchEnd.compareTo(searchStart) < 0) {
                continue;
            }

            long sizeLong = searchEnd.subtract(searchStart) + 1;
            if (sizeLong < pattern.length || sizeLong > Integer.MAX_VALUE) {
                continue;
            }

            byte[] data = new byte[(int) sizeLong];
            int bytesRead;
            try {
                bytesRead = program.getMemory().getBytes(searchStart, data);
            } catch (MemoryAccessException e) {
                continue;
            }
            if (bytesRead < pattern.length) {
                continue;
            }

            for (int index = 0; index <= bytesRead - pattern.length && hits.size() < hitLimit; index++) {
                if (!matchesBytePattern(data, index, pattern)) {
                    continue;
                }
                Address hitAddress = searchStart.add(index);
                hits.add(String.format(
                    "hit=%s\tblock=%s\tcontext=%s",
                    hitAddress,
                    block.getName(),
                    formatByteContext(data, index, pattern.length, 6)));
            }

            if (hits.size() >= hitLimit) {
                break;
            }
        }

        if (hits.isEmpty()) {
            return "No byte-pattern hits found";
        }

        return "pattern=" + patternText.trim() + "\n"
            + "hits=" + hits.size() + "\n"
            + String.join("\n", hits);
    }

    private int[] parseBytePattern(String patternText) {
        String normalized = patternText.trim().replace(',', ' ');
        List<String> tokens = new ArrayList<>();
        if (normalized.contains(" ") || normalized.contains("\t")) {
            for (String token : normalized.split("\\s+")) {
                if (!token.isBlank()) {
                    tokens.add(token);
                }
            }
        } else {
            String compact = normalized.replace("0x", "").replace("0X", "");
            if ((compact.length() & 1) != 0) {
                throw new IllegalArgumentException("compact patterns must contain an even number of hex digits");
            }
            for (int index = 0; index < compact.length(); index += 2) {
                tokens.add(compact.substring(index, index + 2));
            }
        }

        if (tokens.isEmpty()) {
            throw new IllegalArgumentException("pattern is empty");
        }

        int[] pattern = new int[tokens.size()];
        for (int index = 0; index < tokens.size(); index++) {
            String token = tokens.get(index).trim();
            if (token.equals("??") || token.equals("**")) {
                pattern[index] = -1;
                continue;
            }

            token = token.replace("0x", "").replace("0X", "");
            if (!token.matches("[0-9a-fA-F]{2}")) {
                throw new IllegalArgumentException("invalid byte token '" + token + "'");
            }
            pattern[index] = Integer.parseInt(token, 16);
        }
        return pattern;
    }

    private boolean matchesBytePattern(byte[] data, int offset, int[] pattern) {
        for (int index = 0; index < pattern.length; index++) {
            int expected = pattern[index];
            if (expected >= 0 && (data[offset + index] & 0xff) != expected) {
                return false;
            }
        }
        return true;
    }

    private String formatByteContext(byte[] data, int offset, int patternLength, int radius) {
        int start = Math.max(0, offset - radius);
        int end = Math.min(data.length, offset + patternLength + radius);
        StringBuilder out = new StringBuilder();
        for (int index = start; index < end; index++) {
            if (out.length() > 0) {
                out.append(' ');
            }
            if (index == offset) {
                out.append('[');
            }
            out.append(String.format("%02x", data[index] & 0xff));
            if (index == offset + patternLength - 1) {
                out.append(']');
            }
        }
        return out.toString();
    }

    private String getCallers(Program program, String targetIdentifier, boolean includeNear,
                              boolean includeFar, boolean includeJumps, int limit) {
        if (program == null) return "No program loaded";
        if (targetIdentifier == null || targetIdentifier.isBlank()) return "target is required";

        Function targetFunction = resolveFunctionIdentifier(program, targetIdentifier);
        if (targetFunction == null) {
            return "No function found for target " + targetIdentifier;
        }

        int maxResults = Math.max(1, Math.min(limit, 1000));
        LinkedHashMap<String, String> results = new LinkedHashMap<>();
        Address entry = targetFunction.getEntryPoint();

        ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entry);
        while (refIter.hasNext() && results.size() < maxResults) {
            Reference ref = refIter.next();
            RefType refType = ref.getReferenceType();
            if (!includeRefType(refType, includeJumps)) {
                continue;
            }
            if (!includeCallScope(refType, includeNear, includeFar)) {
                continue;
            }
            Address fromAddr = ref.getFromAddress();
            results.putIfAbsent(
                fromAddr.toString(),
                formatCallerLine(program, fromAddr, entry, targetFunction, refType, "xref"));
        }

        InstructionIterator it = program.getListing().getInstructions(true);
        while (it.hasNext() && results.size() < maxResults) {
            Instruction instruction = it.next();
            String kind = classifyInstructionKind(instruction);
            if (kind.equals("other")) {
                continue;
            }
            if (kind.equals("jump") && !includeJumps) {
                continue;
            }
            if (kind.equals("call") && !includeNear && !includeFar) {
                continue;
            }

            Address[] flows = instruction.getFlows();
            if (flows == null || flows.length == 0) {
                continue;
            }
            for (Address flow : flows) {
                if (!entry.equals(flow)) {
                    continue;
                }
                String key = instruction.getAddress().toString();
                results.putIfAbsent(
                    key,
                    formatCallerLine(program, instruction.getAddress(), entry, targetFunction,
                        instruction.getFlowType(), "instruction_scan"));
                break;
            }
        }

        if (results.isEmpty()) {
            return "No callers found for " + targetFunction.getName();
        }

        return "target_function=" + targetFunction.getName() + "\n"
            + "target_entry=" + targetFunction.getEntryPoint() + "\n"
            + String.join("\n", results.values());
    }

    private boolean includeRefType(RefType refType, boolean includeJumps) {
        if (refType == null) {
            return false;
        }
        if (refType.isCall()) {
            return true;
        }
        return includeJumps && refType.isJump();
    }

    private boolean includeCallScope(RefType refType, boolean includeNear, boolean includeFar) {
        if (refType == null || !refType.isCall()) {
            return true;
        }
        String name = refType.getName().toLowerCase(Locale.ROOT);
        boolean isFar = name.contains("far") || name.contains("external");
        if (isFar) {
            return includeFar;
        }
        return includeNear;
    }

    private String classifyInstructionKind(Instruction instruction) {
        if (instruction == null) {
            return "other";
        }
        RefType flowType = instruction.getFlowType();
        if (flowType != null) {
            if (flowType.isCall()) {
                return "call";
            }
            if (flowType.isJump()) {
                return "jump";
            }
        }
        String mnemonic = instruction.getMnemonicString().toLowerCase(Locale.ROOT);
        if (mnemonic.startsWith("call")) {
            return "call";
        }
        if (mnemonic.startsWith("jmp") || mnemonic.startsWith("j")) {
            return "jump";
        }
        return "other";
    }

    private String formatCallerLine(Program program, Address fromAddr, Address toAddr,
                                    Function targetFunction, RefType refType, String source) {
        Function fromFunction = program.getFunctionManager().getFunctionContaining(fromAddr);
        String refName = refType == null ? "<none>" : refType.getName();
        return String.format(
            "from=%s\tfrom_function=%s\tto=%s\tto_function=%s\tref_type=%s\tref_kind=%s\tsource=%s",
            fromAddr,
            safeFunctionName(fromFunction),
            toAddr,
            safeFunctionName(targetFunction),
            refName,
            classifyRefKind(refType),
            source);
    }

    private String listProjectPrograms(String projectDir, String projectName,
                                       String folderPath, boolean recursive) {
        String resolvedProjectDir = trimToNull(projectDir);
        String resolvedProjectName = trimToNull(projectName);
        String resolvedFolderPath = normalizeFolderPath(folderPath);

        if (resolvedProjectDir == null || resolvedProjectName == null) {
            Program currentProgram = getCurrentProgram();
            if (currentProgram != null && currentProgram.getDomainFile() != null &&
                currentProgram.getDomainFile().getProjectLocator() != null) {
                ghidra.framework.model.ProjectLocator locator = currentProgram.getDomainFile().getProjectLocator();
                if (resolvedProjectDir == null) {
                    resolvedProjectDir = locator.getLocation();
                }
                if (resolvedProjectName == null) {
                    resolvedProjectName = locator.getName();
                }
            }
        }

        if (resolvedProjectDir == null || resolvedProjectName == null) {
            return "project_dir and project_name are required when no current project is available";
        }

        Object ghidraProjectHandle = null;
        try {
            ghidraProjectHandle = openExplicitProjectHandle(resolvedProjectDir, resolvedProjectName);
            ghidra.framework.model.ProjectData projectData = getProjectDataFromHandle(ghidraProjectHandle);
            if (projectData == null) {
                return "Failed to resolve project data";
            }

            ghidra.framework.model.DomainFolder folder = "/".equals(resolvedFolderPath)
                ? projectData.getRootFolder()
                : projectData.getFolder(resolvedFolderPath);
            if (folder == null) {
                return "No folder found at " + resolvedFolderPath;
            }

            List<String> lines = new ArrayList<>();
            collectProjectPrograms(folder, recursive, lines);
            Collections.sort(lines);

            int programCount = 0;
            int folderCount = 0;
            for (String line : lines) {
                if (line.startsWith("entry_type=program\t")) {
                    programCount++;
                } else if (line.startsWith("entry_type=folder\t")) {
                    folderCount++;
                }
            }

            StringBuilder out = new StringBuilder();
            out.append("project_dir=").append(resolvedProjectDir).append("\n")
                .append("project_name=").append(resolvedProjectName).append("\n")
                .append("folder_path=").append(resolvedFolderPath).append("\n")
                .append("recursive=").append(recursive).append("\n")
                .append("folder_count=").append(folderCount).append("\n")
                .append("program_count=").append(programCount);
            if (!lines.isEmpty()) {
                out.append("\n").append(String.join("\n", lines));
            }
            return out.toString();
        } catch (Exception e) {
            Throwable cause = unwrapReflectionFailure(e);
            return "Failed to list project programs: " + cause.getMessage();
        } finally {
            ghidra.framework.model.Project project = getProjectFromHandle(ghidraProjectHandle);
            if (project != null) {
                try {
                    if (!project.isClosed()) {
                        project.close();
                    }
                } catch (Exception e) {
                    Msg.debug(this, "Failed to close project after inventory listing", e);
                }
            }
        }
    }

    private void collectProjectPrograms(ghidra.framework.model.DomainFolder folder, boolean recursive,
                                        List<String> lines) {
        String folderPath = normalizeFolderPath(folder.getPathname());
        lines.add(String.format(
            "entry_type=folder\tfolder_path=%s\tname=%s",
            folderPath,
            safeValueForResponse(folder.getName())));

        for (ghidra.framework.model.DomainFile file : folder.getFiles()) {
            String parentPath = file.getParent() == null ? "/" : normalizeFolderPath(file.getParent().getPathname());
            boolean currentlyOpen = false;
            try {
                currentlyOpen = file.getOpenedDomainObject(this) != null;
            } catch (Exception ignored) {
                // Best-effort only.
            }
            lines.add(String.format(
                "entry_type=program\tfolder_path=%s\tprogram_name=%s\tcontent_type=%s\tread_only=%s\tversioned=%s\tcurrently_open=%s",
                parentPath,
                file.getName(),
                safeValueForResponse(file.getContentType()),
                file.isReadOnly(),
                file.isVersioned(),
                currentlyOpen));
        }

        if (!recursive) {
            return;
        }

        for (ghidra.framework.model.DomainFolder child : folder.getFolders()) {
            collectProjectPrograms(child, true, lines);
        }
    }

    private String compareRegions(Program leftProgram, Program rightProgram,
                                  String leftStartStr, String leftEndStr,
                                  String rightStartStr, String rightEndStr,
                                  String mode, int maxDiffs) {
        if (leftProgram == null || rightProgram == null) {
            return "Both left and right programs are required";
        }

        Address leftStart = parseAddress(leftProgram, leftStartStr);
        Address leftEnd = parseAddress(leftProgram, leftEndStr);
        Address rightStart = parseAddress(rightProgram, rightStartStr);
        Address rightEnd = parseAddress(rightProgram, rightEndStr);
        if (leftStart == null || leftEnd == null || rightStart == null || rightEnd == null) {
            return "left_start, left_end, right_start, and right_end must all be valid addresses";
        }

        String compareMode = normalizeWhitespace(mode).isBlank() ? "bytes" : normalizeWhitespace(mode).toLowerCase(Locale.ROOT);
        int diffLimit = Math.max(1, Math.min(maxDiffs, 500));
        if (compareMode.equals("bytes") || compareMode.equals("words")) {
            return compareByteRegions(leftProgram, rightProgram, leftStart, leftEnd, rightStart, rightEnd,
                compareMode.equals("words") ? 2 : 1, compareMode, diffLimit);
        }
        if (compareMode.equals("disasm")) {
            return buildTextComparisonReport(
                compareMode,
                disassembleRegion(leftProgram, leftStart.toString(), leftEnd.toString()),
                disassembleRegion(rightProgram, rightStart.toString(), rightEnd.toString()),
                diffLimit);
        }
        if (compareMode.equals("strings")) {
            return compareStringLists(
                compareMode,
                collectStringsInRange(leftProgram, leftStart, leftEnd, Integer.MAX_VALUE),
                collectStringsInRange(rightProgram, rightStart, rightEnd, Integer.MAX_VALUE),
                diffLimit);
        }
        return "Unsupported compare mode: " + compareMode;
    }

    private String compareByteRegions(Program leftProgram, Program rightProgram,
                                      Address leftStart, Address leftEnd,
                                      Address rightStart, Address rightEnd,
                                      int unitSize, String mode, int maxDiffs) {
        byte[] leftBytes;
        byte[] rightBytes;
        try {
            leftBytes = readBytes(leftProgram, leftStart, leftEnd, 1024 * 1024);
            rightBytes = readBytes(rightProgram, rightStart, rightEnd, 1024 * 1024);
        } catch (IOException e) {
            return "Failed to read comparison regions: " + e.getMessage();
        }

        int leftUnits = leftBytes.length / unitSize;
        int rightUnits = rightBytes.length / unitSize;
        int totalUnits = Math.max(leftUnits, rightUnits);
        int comparableUnits = Math.min(leftUnits, rightUnits);
        int equalUnits = 0;
        List<String> diffs = new ArrayList<>();

        for (int index = 0; index < comparableUnits; index++) {
            boolean equal = true;
            for (int step = 0; step < unitSize; step++) {
                if (leftBytes[index * unitSize + step] != rightBytes[index * unitSize + step]) {
                    equal = false;
                    break;
                }
            }

            if (equal) {
                equalUnits++;
                continue;
            }
            if (diffs.size() < maxDiffs) {
                diffs.add(String.format(
                    "offset=0x%x\tleft=%s\tright=%s",
                    index * unitSize,
                    formatUnitHex(leftBytes, index * unitSize, unitSize),
                    formatUnitHex(rightBytes, index * unitSize, unitSize)));
            }
        }

        if (leftUnits != rightUnits && diffs.size() < maxDiffs) {
            diffs.add("length_mismatch left_units=" + leftUnits + " right_units=" + rightUnits);
        }

        StringBuilder out = new StringBuilder();
        out.append("comparison_mode=").append(mode).append("\n")
            .append("left_size=").append(leftBytes.length).append("\n")
            .append("right_size=").append(rightBytes.length).append("\n")
            .append("equal_units=").append(equalUnits).append("\n")
            .append("total_units=").append(totalUnits).append("\n")
            .append("similarity=").append(formatSimilarity(equalUnits, totalUnits));
        if (!diffs.isEmpty()) {
            out.append("\n").append(String.join("\n", diffs));
        }
        return out.toString();
    }

    private String compareStrings(Program leftProgram, Program rightProgram, String filter, int maxResults) {
        if (leftProgram == null || rightProgram == null) {
            return "Both left and right programs are required";
        }
        return compareStringLists(
            "strings",
            collectProgramStrings(leftProgram, filter, Math.max(1, Math.min(maxResults, 5000))),
            collectProgramStrings(rightProgram, filter, Math.max(1, Math.min(maxResults, 5000))),
            Math.max(1, Math.min(maxResults, 500)));
    }

    private String compareFunctions(Program leftProgram, Program rightProgram,
                                    String leftFunctionId, String rightFunctionId,
                                    String mode, int limit) {
        if (leftProgram == null || rightProgram == null) {
            return "Both left and right programs are required";
        }

        Function leftFunction = resolveFunctionIdentifier(leftProgram, leftFunctionId);
        Function rightFunction = resolveFunctionIdentifier(rightProgram, rightFunctionId);
        if (leftFunction == null || rightFunction == null) {
            return "Both left_function and right_function must resolve to a function";
        }

        String compareMode = normalizeWhitespace(mode).isBlank() ? "signature" : normalizeWhitespace(mode).toLowerCase(Locale.ROOT);
        String header = "left_function=" + leftFunction.getName() + "@" + leftFunction.getEntryPoint() + "\n"
            + "right_function=" + rightFunction.getName() + "@" + rightFunction.getEntryPoint();

        if (compareMode.equals("signature")) {
            return header + "\n" + buildTextComparisonReport(
                compareMode,
                leftFunction.getSignature().toString(),
                rightFunction.getSignature().toString(),
                Math.max(1, Math.min(limit, 100)));
        }
        if (compareMode.equals("disasm")) {
            return header + "\n" + buildTextComparisonReport(
                compareMode,
                disassembleFunction(leftProgram, leftFunction.getEntryPoint().toString()),
                disassembleFunction(rightProgram, rightFunction.getEntryPoint().toString()),
                Math.max(1, Math.min(limit, 200)));
        }
        if (compareMode.equals("decompile")) {
            return header + "\n" + buildTextComparisonReport(
                compareMode,
                decompileFunctionByAddress(leftProgram, leftFunction.getEntryPoint().toString()),
                decompileFunctionByAddress(rightProgram, rightFunction.getEntryPoint().toString()),
                Math.max(1, Math.min(limit, 200)));
        }
        if (compareMode.equals("xrefs")) {
            return header + "\n" + buildTextComparisonReport(
                compareMode,
                getCallers(leftProgram, leftFunction.getEntryPoint().toString(), true, true, true, limit),
                getCallers(rightProgram, rightFunction.getEntryPoint().toString(), true, true, true, limit),
                Math.max(1, Math.min(limit, 200)));
        }
        return "Unsupported compare mode: " + compareMode;
    }

    private String portSymbols(Map<String, String> params, String mappings, String apply,
                               String provenanceCommentTemplate, boolean dryRun) {
        if (mappings == null || mappings.isBlank()) {
            return "mappings is required";
        }

        ProgramTargetContext sourceContext = resolveTargetContext(params, "source_");
        if (sourceContext.hasError()) {
            return sourceContext.errorMessage;
        }

        ProgramTargetContext targetContext = resolveTargetContext(params, "target_");
        if (targetContext.hasError()) {
            closeWriteTargetContext(sourceContext);
            return targetContext.errorMessage;
        }

        String applyMode = normalizeWhitespace(apply).isBlank() ? "both" : normalizeWhitespace(apply).toLowerCase(Locale.ROOT);
        boolean applyNames = applyMode.equals("both") || applyMode.equals("names");
        boolean applyComments = applyMode.equals("both") || applyMode.equals("comments");
        if (!applyNames && !applyComments) {
            closeWriteTargetContext(sourceContext);
            closeWriteTargetContext(targetContext);
            return "apply must be one of: names, comments, both";
        }

        AtomicBoolean committed = new AtomicBoolean(false);
        List<String> lines = new ArrayList<>();

        try {
            int tx = targetContext.program.startTransaction("Port symbols");
            try {
                for (String line : mappings.split("\\r?\\n")) {
                    if (line.isBlank()) {
                        continue;
                    }
                    String[] parts = line.split("\\t");
                    if (parts.length < 2) {
                        lines.add("status=invalid_mapping\tline=" + safeValueForResponse(line));
                        continue;
                    }

                    Address sourceAddr = parseAddress(sourceContext.program, parts[0].trim());
                    Address targetAddr = parseAddress(targetContext.program, parts[1].trim());
                    if (sourceAddr == null || targetAddr == null) {
                        lines.add("status=invalid_address\tsource=" + safeValueForResponse(parts[0])
                            + "\ttarget=" + safeValueForResponse(parts[1]));
                        continue;
                    }

                    Symbol sourceSymbol = sourceContext.program.getSymbolTable().getPrimarySymbol(sourceAddr);
                    String sourcePre = sourceContext.program.getListing().getComment(CodeUnit.PRE_COMMENT, sourceAddr);
                    String sourceEol = sourceContext.program.getListing().getComment(CodeUnit.EOL_COMMENT, sourceAddr);

                    if (sourceSymbol == null && !applyComments) {
                        lines.add("status=no_source_symbol\tsource=" + sourceAddr + "\ttarget=" + targetAddr);
                        continue;
                    }

                    if (!dryRun) {
                        if (applyNames && sourceSymbol != null) {
                            Symbol targetSymbol = targetContext.program.getSymbolTable().getPrimarySymbol(targetAddr);
                            if (targetSymbol != null) {
                                targetSymbol.setName(sourceSymbol.getName(), SourceType.USER_DEFINED);
                            } else {
                                targetContext.program.getSymbolTable().createLabel(
                                    targetAddr, sourceSymbol.getName(), SourceType.USER_DEFINED);
                            }
                        }
                        if (applyComments) {
                            if (sourcePre != null && !sourcePre.isBlank()) {
                                targetContext.program.getListing().setComment(
                                    targetAddr, CodeUnit.PRE_COMMENT,
                                    appendProvenance(sourcePre, provenanceCommentTemplate,
                                        sourceContext.program, targetContext.program,
                                        sourceAddr, targetAddr, sourceSymbol));
                            }
                            if (sourceEol != null && !sourceEol.isBlank()) {
                                targetContext.program.getListing().setComment(
                                    targetAddr, CodeUnit.EOL_COMMENT,
                                    appendProvenance(sourceEol, provenanceCommentTemplate,
                                        sourceContext.program, targetContext.program,
                                        sourceAddr, targetAddr, sourceSymbol));
                            }
                        }
                    }

                    lines.add("status=" + (dryRun ? "dry_run" : "applied")
                        + "\tsource=" + sourceAddr
                        + "\ttarget=" + targetAddr
                        + "\tname=" + safeValueForResponse(sourceSymbol != null ? sourceSymbol.getName() : "<none>")
                        + "\tported_comments=" + applyComments);
                }
                committed.set(!dryRun);
            } finally {
                targetContext.program.endTransaction(tx, committed.get());
            }

            String response = formatDualTargetedResponse(
                sourceContext,
                targetContext,
                "apply_mode=" + applyMode + "\n"
                    + "dry_run=" + dryRun + "\n"
                    + String.join("\n", lines));
            if (!dryRun && committed.get() && targetContext.explicitTarget) {
                response = response + "\n" + saveExplicitTargetIfNeeded(targetContext);
            }
            return response;
        } catch (Exception e) {
            return "Failed to port symbols: " + e.getMessage();
        } finally {
            closeWriteTargetContext(sourceContext);
            closeWriteTargetContext(targetContext);
        }
    }

    private String appendProvenance(String baseComment, String template,
                                    Program sourceProgram, Program targetProgram,
                                    Address sourceAddr, Address targetAddr, Symbol sourceSymbol) {
        String provenance = trimToNull(template);
        if (provenance == null) {
            provenance = "ported_from={source_program}@{source_address}";
        }
        provenance = provenance
            .replace("{source_program}", sourceProgram.getName())
            .replace("{target_program}", targetProgram.getName())
            .replace("{source_address}", sourceAddr.toString())
            .replace("{target_address}", targetAddr.toString())
            .replace("{symbol}", sourceSymbol == null ? "<none>" : sourceSymbol.getName());
        if (baseComment == null || baseComment.isBlank()) {
            return provenance;
        }
        if (baseComment.contains(provenance)) {
            return baseComment;
        }
        return baseComment + "\n" + provenance;
    }

    private byte[] readBytes(Program program, Address start, Address end, int maxBytes) throws IOException {
        long sizeLong = end.subtract(start) + 1;
        if (sizeLong <= 0 || sizeLong > maxBytes) {
            throw new IOException("requested region size is out of supported range (1.." + maxBytes + " bytes)");
        }
        byte[] data = new byte[(int) sizeLong];
        try {
            int bytesRead = program.getMemory().getBytes(start, data);
            if (bytesRead != data.length) {
                return Arrays.copyOf(data, Math.max(0, bytesRead));
            }
            return data;
        } catch (MemoryAccessException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    private String formatUnitHex(byte[] data, int offset, int unitSize) {
        StringBuilder out = new StringBuilder();
        for (int index = 0; index < unitSize && offset + index < data.length; index++) {
            if (index > 0) {
                out.append(' ');
            }
            out.append(String.format("%02x", data[offset + index] & 0xff));
        }
        return out.toString();
    }

    private String buildTextComparisonReport(String mode, String leftBody, String rightBody, int maxDiffs) {
        List<String> leftLines = normalizeComparisonLines(leftBody);
        List<String> rightLines = normalizeComparisonLines(rightBody);
        LinkedHashSet<String> leftSet = new LinkedHashSet<>(leftLines);
        LinkedHashSet<String> rightSet = new LinkedHashSet<>(rightLines);

        int shared = 0;
        for (String line : leftSet) {
            if (rightSet.contains(line)) {
                shared++;
            }
        }

        List<String> leftOnly = new ArrayList<>();
        for (String line : leftSet) {
            if (!rightSet.contains(line)) {
                leftOnly.add("left_only=" + line);
                if (leftOnly.size() >= maxDiffs) {
                    break;
                }
            }
        }

        List<String> rightOnly = new ArrayList<>();
        for (String line : rightSet) {
            if (!leftSet.contains(line)) {
                rightOnly.add("right_only=" + line);
                if (rightOnly.size() >= maxDiffs) {
                    break;
                }
            }
        }

        StringBuilder out = new StringBuilder();
        out.append("comparison_mode=").append(mode).append("\n")
            .append("left_items=").append(leftSet.size()).append("\n")
            .append("right_items=").append(rightSet.size()).append("\n")
            .append("shared_items=").append(shared).append("\n")
            .append("similarity=").append(formatSimilarity(shared, leftSet.size() + rightSet.size() - shared));
        if (!leftOnly.isEmpty()) {
            out.append("\n").append(String.join("\n", leftOnly));
        }
        if (!rightOnly.isEmpty()) {
            out.append("\n").append(String.join("\n", rightOnly));
        }
        return out.toString();
    }

    private List<String> normalizeComparisonLines(String body) {
        List<String> lines = new ArrayList<>();
        if (body == null || body.isBlank()) {
            return lines;
        }
        for (String line : body.split("\\r?\\n")) {
            String normalized = line.trim();
            if (!normalized.isEmpty()) {
                lines.add(normalized);
            }
        }
        return lines;
    }

    private String formatSimilarity(int numerator, int denominator) {
        if (denominator <= 0) {
            return "1.000";
        }
        return String.format(Locale.ROOT, "%.3f", (double) numerator / (double) denominator);
    }

    private List<String> collectProgramStrings(Program program, String filter, int maxResults) {
        List<String> lines = new ArrayList<>();
        String loweredFilter = filter == null ? null : filter.toLowerCase(Locale.ROOT);
        DataIterator dataIt = program.getListing().getDefinedData(true);
        while (dataIt.hasNext() && lines.size() < maxResults) {
            Data data = dataIt.next();
            if (!isStringData(data)) {
                continue;
            }
            String value = data.getValue() != null ? data.getValue().toString() : "";
            if (loweredFilter != null && !value.toLowerCase(Locale.ROOT).contains(loweredFilter)) {
                continue;
            }
            lines.add(String.format("%s\t%s", data.getAddress(), escapeString(value)));
        }
        return lines;
    }

    private List<String> collectStringsInRange(Program program, Address start, Address end, int maxResults) {
        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(start, true);
        while (dataIt.hasNext() && lines.size() < maxResults) {
            Data data = dataIt.next();
            if (data.getAddress().compareTo(end) > 0) {
                break;
            }
            if (!isStringData(data)) {
                continue;
            }
            String value = data.getValue() != null ? data.getValue().toString() : "";
            lines.add(String.format("%s\t%s", data.getAddress(), escapeString(value)));
        }
        return lines;
    }

    private String compareStringLists(String mode, List<String> leftLines, List<String> rightLines, int maxDiffs) {
        Map<String, List<String>> leftByValue = groupStringsByValue(leftLines);
        Map<String, List<String>> rightByValue = groupStringsByValue(rightLines);

        int shared = 0;
        for (String value : leftByValue.keySet()) {
            if (rightByValue.containsKey(value)) {
                shared++;
            }
        }

        List<String> output = new ArrayList<>();
        output.add("comparison_mode=" + mode);
        output.add("left_values=" + leftByValue.size());
        output.add("right_values=" + rightByValue.size());
        output.add("shared_values=" + shared);
        output.add("similarity=" + formatSimilarity(shared, leftByValue.size() + rightByValue.size() - shared));

        int emitted = 0;
        for (Map.Entry<String, List<String>> entry : leftByValue.entrySet()) {
            if (!rightByValue.containsKey(entry.getKey())) {
                output.add("left_only_value=" + entry.getKey());
                emitted++;
                if (emitted >= maxDiffs) {
                    break;
                }
            }
        }

        emitted = 0;
        for (Map.Entry<String, List<String>> entry : rightByValue.entrySet()) {
            if (!leftByValue.containsKey(entry.getKey())) {
                output.add("right_only_value=" + entry.getKey());
                emitted++;
                if (emitted >= maxDiffs) {
                    break;
                }
            }
        }

        return String.join("\n", output);
    }

    private Map<String, List<String>> groupStringsByValue(List<String> lines) {
        LinkedHashMap<String, List<String>> grouped = new LinkedHashMap<>();
        for (String line : lines) {
            String[] parts = line.split("\\t", 2);
            String value = parts.length == 2 ? parts[1] : line;
            grouped.computeIfAbsent(value, ignored -> new ArrayList<>()).add(parts[0]);
        }
        return grouped;
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
        return applyProgramEditPlan(program, plan, dryRun).message;
    }

    private String applyProgramEditPlan(String plan, boolean dryRun, Map<String, String> params) {
        ProgramTargetContext context = resolveWriteTargetContext(params);
        if (context.hasError()) {
            return context.errorMessage;
        }

        try {
            OperationResult result = applyProgramEditPlan(context.program, plan, dryRun);
            String response = formatTargetedResponse(context, result.message);
            if (result.success && context.explicitTarget && !dryRun) {
                response = response + "\n" + saveExplicitTargetIfNeeded(context);
            }
            return response;
        } finally {
            closeWriteTargetContext(context);
        }
    }

    private OperationResult applyProgramEditPlan(Program program, String plan, boolean dryRun) {
        if (plan == null || plan.isBlank()) return new OperationResult(false, "plan is required");

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
                        String result = renameFunctionByAddress(program, parts[1], parts[2]) ? "ok" : "failed";
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
                        boolean ok = setDisassemblyComment(program, parts[1], parts[2]);
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
                        boolean ok = setDecompilerComment(program, parts[1], parts[2]);
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
                        String result = deleteFunctionByAddress(program, parts[1]).message;
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
                        String result = createFunctionByAddress(program, parts[1], parts[2], parts[3], parts[4], comment).message;
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
        return new OperationResult(failCount == 0, out.toString());
    }

    private String reanalyzeRegion(String startStr, String endStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return reanalyzeRegion(program, startStr, endStr);
    }

    private String reanalyzeRegion(Program program, String startStr, String endStr) {
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
        return patchBytesAndReanalyze(program, startStr, bytesStr, comment).message;
    }

    private String patchBytesAndReanalyze(String startStr, String bytesStr, String comment,
                                          Map<String, String> params) {
        ProgramTargetContext context = resolveWriteTargetContext(params);
        if (context.hasError()) {
            return context.errorMessage;
        }

        try {
            OperationResult result = patchBytesAndReanalyze(context.program, startStr, bytesStr, comment);
            String response = formatTargetedResponse(context, result.message);
            if (result.success && context.explicitTarget) {
                response = response + "\n" + saveExplicitTargetIfNeeded(context);
            }
            return response;
        } finally {
            closeWriteTargetContext(context);
        }
    }

    private OperationResult patchBytesAndReanalyze(Program program, String startStr,
                                                   String bytesStr, String comment) {
        if (startStr == null || startStr.isBlank()) return new OperationResult(false, "start is required");
        if (bytesStr == null || bytesStr.isBlank()) return new OperationResult(false, "bytes is required");

        byte[] patchBytes;
        try {
            patchBytes = parseHexBytes(bytesStr);
        } catch (IllegalArgumentException e) {
            return new OperationResult(false, "Invalid bytes: " + e.getMessage());
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
            return new OperationResult(false, "Patch failed on Swing thread: " + e.getMessage());
        }

        if (!committed.get()) {
            return new OperationResult(false, out.toString());
        }

        try {
            Address start = program.getAddressFactory().getAddress(startStr);
            Address end = start.add(patchBytes.length - 1L);
            String reanalysis = reanalyzeRegion(program, start.toString(), end.toString());
            return new OperationResult(true, out.append("\n").append(reanalysis).toString());
        } catch (Exception e) {
            return new OperationResult(true,
                out.append("\nReanalysis skipped: ").append(e.getMessage()).toString());
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

    private String getRuntimeCapabilities() {
        Program program = getCurrentProgram();
        ReadonlyScriptCapability capability = probeReadonlyScriptCapability(program);
        WriteScriptCapability writeCapability = probeWriteScriptCapability(program);

        StringBuilder out = new StringBuilder();
        out.append("active_program_loaded=").append(program != null).append("\n");
        if (program != null) {
            out.append("active_program=").append(program.getName()).append("\n");
        }
        out.append("readonly_script_supported=").append(capability.supported).append("\n");
        out.append("readonly_script_status=").append(capability.status).append("\n");
        out.append("readonly_script_reason=").append(capability.reason).append("\n");
        if (capability.detail != null && !capability.detail.isBlank()) {
            out.append("readonly_script_detail=").append(escapeNonAscii(capability.detail)).append("\n");
        }
        out.append("write_script_supported=").append(writeCapability.supported).append("\n");
        out.append("write_script_status=").append(writeCapability.status).append("\n");
        out.append("write_script_reason=").append(writeCapability.reason).append("\n");
        if (writeCapability.detail != null && !writeCapability.detail.isBlank()) {
            out.append("write_script_detail=").append(escapeNonAscii(writeCapability.detail)).append("\n");
        }
        out.append("write_script_dry_run_supported=true\n");
        out.append("read_only_program_open_supported=false\n");
        out.append("explicit_write_target_selection_supported=true\n");
        out.append("explicit_write_target_fields=project_dir,project_name,folder_path,program_name");
        return out.toString();
    }

    private String openCurrentProgramReadonly(int version, boolean makeCurrent) {
        return "unsupported: MCP will not open programs in read-only mode; use the live writable program context instead";
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

        ReadonlyScriptCapability capability = probeReadonlyScriptCapability(program);
        if (!capability.supported) {
            return formatReadonlyUnsupportedResponse(capability);
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

    private String runWriteScript(String scriptPath, String scriptText, boolean dryRun,
                                  Map<String, String> params) {
        ProgramTargetContext context = resolveWriteTargetContext(params);
        if (context.hasError()) {
            return context.errorMessage;
        }

        try {
            WriteScriptCapability capability = probeWriteScriptCapability(context.program);
            if (!capability.supported) {
                return formatTargetedResponse(context, formatWriteUnsupportedResponse(capability));
            }

            boolean hasPath = scriptPath != null && !scriptPath.isBlank();
            boolean hasText = scriptText != null && !scriptText.isBlank();
            if (!hasPath && !hasText) {
                return formatTargetedResponse(context, "Provide script_path or script_text");
            }
            if (hasPath && hasText) {
                return formatTargetedResponse(context, "Provide only one of script_path or script_text");
            }

            generic.jar.ResourceFile scriptFile = null;
            boolean deleteAfterRun = false;
            int tx = -1;
            boolean commit = false;
            try {
                if (hasPath) {
                    scriptFile = resolveScriptPath(scriptPath);
                    if (scriptFile == null || !scriptFile.exists()) {
                        return formatTargetedResponse(context, "Script file not found: " + scriptPath);
                    }
                }
                else {
                    validateWriteScriptText(scriptText);
                    scriptFile = writeTempScript(scriptText, "mcp_write_");
                    deleteAfterRun = true;
                }

                String loadedScriptText = loadScriptTextForValidation(scriptFile);
                validateWriteScriptText(loadedScriptText);

                if (dryRun) {
                    return formatTargetedResponse(context,
                        "status=dry_run\n"
                            + "operation=run_write_script\n"
                            + "dry_run=true\n"
                            + "validated=true\n"
                            + "target_program=" + safeValueForResponse(context.program.getName()));
                }

                GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
                if (provider == null) {
                    return formatTargetedResponse(context, "No script provider for file: " + scriptFile.getName());
                }

                StringWriter outputBuffer = new StringWriter();
                PrintWriter writer = new PrintWriter(outputBuffer, true);
                GhidraScript script = provider.getScriptInstance(scriptFile, writer);
                if (script == null) {
                    return formatTargetedResponse(context, "Unable to load script");
                }

                GhidraState state = new GhidraState(
                    tool,
                    tool.getProject(),
                    context.program,
                    null,
                    null,
                    null);

                tx = context.program.startTransaction("Run write script");
                script.execute(state, new ConsoleTaskMonitor(), writer);
                commit = true;

                StringBuilder out = new StringBuilder();
                out.append("status=ok\n")
                    .append("operation=run_write_script\n")
                    .append("dry_run=false\n")
                    .append("transaction_committed=true\n")
                    .append("target_program=").append(safeValueForResponse(context.program.getName()));

                String output = outputBuffer.toString().trim();
                if (!output.isBlank()) {
                    out.append("\nscript_output_begin\n")
                        .append(output)
                        .append("\nscript_output_end");
                }
                if (context.explicitTarget) {
                    out.append("\n").append(saveExplicitTargetIfNeeded(context));
                }
                return formatTargetedResponse(context, out.toString());
            } catch (Exception e) {
                Throwable cause = unwrapReflectionFailure(e);
                String detail = cause.getMessage() == null ? cause.toString() : cause.getMessage();
                return formatTargetedResponse(context,
                    "status=failed\n"
                        + "operation=run_write_script\n"
                        + "dry_run=" + dryRun + "\n"
                        + "reason=execution_failed\n"
                        + "detail=" + escapeNonAscii(detail));
            } finally {
                if (tx != -1) {
                    context.program.endTransaction(tx, commit);
                }
                if (deleteAfterRun && scriptFile != null) {
                    scriptFile.delete();
                }
            }
        } finally {
            closeWriteTargetContext(context);
        }
    }

    private String formatReadonlyUnsupportedResponse(ReadonlyScriptCapability capability) {
        return "status=" + capability.status + "\n"
            + "operation=run_readonly_script\n"
            + "reason=" + capability.reason + "\n"
            + "detail=" + escapeNonAscii(capability.detail == null ? "" : capability.detail);
    }

    private String formatWriteUnsupportedResponse(WriteScriptCapability capability) {
        return "status=" + capability.status + "\n"
            + "operation=run_write_script\n"
            + "reason=" + capability.reason + "\n"
            + "detail=" + escapeNonAscii(capability.detail == null ? "" : capability.detail);
    }

    private ReadonlyScriptCapability probeReadonlyScriptCapability(Program program) {
        if (program == null) {
            return new ReadonlyScriptCapability(false, "unsupported", "no_program_loaded",
                "No program loaded");
        }

        generic.jar.ResourceFile scriptFile = null;
        try {
            scriptFile = writeTempReadonlyScript("print(\"__ghidra_mcp_readonly_probe__\")");
            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
            if (provider == null) {
                return new ReadonlyScriptCapability(false, "unsupported", "no_script_provider",
                    "No script provider for file: " + scriptFile.getName());
            }

            StringWriter outputBuffer = new StringWriter();
            PrintWriter writer = new PrintWriter(outputBuffer, true);
            GhidraScript script = provider.getScriptInstance(scriptFile, writer);
            if (script == null) {
                return new ReadonlyScriptCapability(false, "unsupported", "script_load_failed",
                    "Unable to load readonly script provider instance");
            }

            GhidraState state = new GhidraState(
                tool,
                tool.getProject(),
                program,
                null,
                null,
                null);
            script.execute(state, new ConsoleTaskMonitor(), writer);
            return new ReadonlyScriptCapability(true, "supported", "available",
                outputBuffer.toString().trim());
        } catch (Exception e) {
            String message = e.getMessage() == null ? e.toString() : e.getMessage();
            String normalized = message.toLowerCase(Locale.ROOT);
            if (normalized.contains("not started with pyghidra") ||
                normalized.contains("python is not available")) {
                return new ReadonlyScriptCapability(false, "unsupported", "python_not_available", message);
            }
            return new ReadonlyScriptCapability(false, "unsupported", "probe_failed", message);
        } finally {
            if (scriptFile != null) {
                scriptFile.delete();
            }
        }
    }

    private WriteScriptCapability probeWriteScriptCapability(Program program) {
        ReadonlyScriptCapability readonlyCapability = probeReadonlyScriptCapability(program);
        if (!readonlyCapability.supported) {
            return new WriteScriptCapability(false, readonlyCapability.status,
                readonlyCapability.reason, readonlyCapability.detail);
        }
        if (program == null) {
            return new WriteScriptCapability(false, "unsupported", "no_program_loaded", "No program loaded");
        }
        ghidra.framework.model.DomainFile df = program.getDomainFile();
        if (df != null && df.isReadOnly()) {
            return new WriteScriptCapability(false, "unsupported", "read_only_domain_file",
                "Active target domain file is read-only");
        }
        if (!program.canSave()) {
            return new WriteScriptCapability(false, "unsupported", "program_cannot_save",
                "Active target program cannot be saved");
        }
        return new WriteScriptCapability(true, "supported", "available",
            "Live write scripting available for the active writable program context");
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
        return writeTempScript(scriptText, "mcp_readonly_");
    }

    private generic.jar.ResourceFile writeTempScript(String scriptText, String prefix) throws IOException {
        generic.jar.ResourceFile userDir = GhidraScriptUtil.getUserScriptDirectory();
        if (userDir == null) {
            throw new IOException("Ghidra user script directory not available");
        }
        if (!userDir.exists()) {
            userDir.mkdir();
        }

        String filename = prefix + System.currentTimeMillis() + ".py";
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

    private void validateWriteScriptText(String scriptText) {
        if (scriptText == null) {
            throw new IllegalArgumentException("script text is required");
        }

        String text = scriptText.toLowerCase(Locale.ROOT);
        String[] blockedTokens = new String[] {
            "starttransaction(",
            "endtransaction(",
            "setbytes(",
            "putbytes(",
            "patchbyte",
            "patchbytes",
            "creatememoryblock",
            "removememoryblock",
            "openprogram(",
            "openproject(",
            "saveas(",
            "deletefile(",
            "deleteproject(",
            "rundoscommand(",
            "runcommand("};

        for (String token : blockedTokens) {
            if (text.contains(token)) {
                throw new IllegalArgumentException("script rejected by write policy: token " + token);
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
        String bodyStr = new String(body, StandardCharsets.UTF_8).trim();
        if (bodyStr.isEmpty()) {
            return new HashMap<>();
        }

        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        String normalizedContentType = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (normalizedContentType.contains("application/json") || bodyStr.startsWith("{")) {
            return parseJsonPostParams(bodyStr);
        }
        if (normalizedContentType.contains("application/x-www-form-urlencoded") || bodyStr.contains("=")) {
            return parseFormPostParams(bodyStr);
        }
        throw new IOException("unsupported-content-type: expected application/json or application/x-www-form-urlencoded body");
    }

    private Map<String, String> parseFormPostParams(String bodyStr) {
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
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

    private Map<String, String> parseJsonPostParams(String bodyStr) throws IOException {
        Map<String, String> params = new LinkedHashMap<>();
        int index = skipJsonWhitespace(bodyStr, 0);
        if (index >= bodyStr.length() || bodyStr.charAt(index) != '{') {
            throw new IOException("unsupported-content-type: expected a JSON object body");
        }
        index++;

        while (true) {
            index = skipJsonWhitespace(bodyStr, index);
            if (index >= bodyStr.length()) {
                throw new IOException("invalid-json-body: unexpected end of input");
            }
            if (bodyStr.charAt(index) == '}') {
                return params;
            }

            JsonToken keyToken = parseJsonStringToken(bodyStr, index);
            index = skipJsonWhitespace(bodyStr, keyToken.nextIndex);
            if (index >= bodyStr.length() || bodyStr.charAt(index) != ':') {
                throw new IOException("invalid-json-body: expected ':' after key");
            }
            index++;

            JsonToken valueToken = parseJsonValueToken(bodyStr, index);
            params.put(keyToken.value, valueToken.value);
            index = skipJsonWhitespace(bodyStr, valueToken.nextIndex);
            if (index >= bodyStr.length()) {
                throw new IOException("invalid-json-body: unexpected end of input after value");
            }

            char delimiter = bodyStr.charAt(index);
            if (delimiter == ',') {
                index++;
                continue;
            }
            if (delimiter == '}') {
                return params;
            }
            throw new IOException("invalid-json-body: expected ',' or '}'");
        }
    }

    private static class JsonToken {
        private final String value;
        private final int nextIndex;

        private JsonToken(String value, int nextIndex) {
            this.value = value;
            this.nextIndex = nextIndex;
        }
    }

    private int skipJsonWhitespace(String text, int index) {
        int current = index;
        while (current < text.length() && Character.isWhitespace(text.charAt(current))) {
            current++;
        }
        return current;
    }

    private JsonToken parseJsonStringToken(String text, int index) throws IOException {
        int current = skipJsonWhitespace(text, index);
        if (current >= text.length() || text.charAt(current) != '"') {
            throw new IOException("invalid-json-body: expected string token");
        }
        current++;
        StringBuilder out = new StringBuilder();
        while (current < text.length()) {
            char c = text.charAt(current++);
            if (c == '"') {
                return new JsonToken(out.toString(), current);
            }
            if (c == '\\') {
                if (current >= text.length()) {
                    throw new IOException("invalid-json-body: incomplete escape sequence");
                }
                char escaped = text.charAt(current++);
                switch (escaped) {
                    case '"': out.append('"'); break;
                    case '\\': out.append('\\'); break;
                    case '/': out.append('/'); break;
                    case 'b': out.append('\b'); break;
                    case 'f': out.append('\f'); break;
                    case 'n': out.append('\n'); break;
                    case 'r': out.append('\r'); break;
                    case 't': out.append('\t'); break;
                    case 'u':
                        if (current + 4 > text.length()) {
                            throw new IOException("invalid-json-body: incomplete unicode escape");
                        }
                        String hex = text.substring(current, current + 4);
                        current += 4;
                        try {
                            out.append((char) Integer.parseInt(hex, 16));
                        } catch (NumberFormatException e) {
                            throw new IOException("invalid-json-body: bad unicode escape \\u" + hex);
                        }
                        break;
                    default:
                        throw new IOException("invalid-json-body: unsupported escape \\" + escaped);
                }
            }
            else {
                out.append(c);
            }
        }
        throw new IOException("invalid-json-body: unterminated string");
    }

    private JsonToken parseJsonValueToken(String text, int index) throws IOException {
        int current = skipJsonWhitespace(text, index);
        if (current >= text.length()) {
            throw new IOException("invalid-json-body: missing value");
        }
        char c = text.charAt(current);
        if (c == '"') {
            return parseJsonStringToken(text, current);
        }
        if (c == '{' || c == '[') {
            return parseJsonStructuredValue(text, current);
        }

        int start = current;
        while (current < text.length()) {
            char next = text.charAt(current);
            if (next == ',' || next == '}' || next == ']' || Character.isWhitespace(next)) {
                break;
            }
            current++;
        }
        String raw = text.substring(start, current).trim();
        if (raw.isEmpty()) {
            throw new IOException("invalid-json-body: empty value");
        }
        if ("null".equals(raw)) {
            return new JsonToken("", current);
        }
        return new JsonToken(raw, current);
    }

    private JsonToken parseJsonStructuredValue(String text, int index) throws IOException {
        int current = index;
        char opener = text.charAt(current);
        char closer = opener == '{' ? '}' : ']';
        int depth = 0;
        boolean inString = false;
        boolean escaping = false;

        while (current < text.length()) {
            char c = text.charAt(current++);
            if (inString) {
                if (escaping) {
                    escaping = false;
                }
                else if (c == '\\') {
                    escaping = true;
                }
                else if (c == '"') {
                    inString = false;
                }
                continue;
            }

            if (c == '"') {
                inString = true;
                continue;
            }
            if (c == opener) {
                depth++;
                continue;
            }
            if (c == closer) {
                depth--;
                if (depth == 0) {
                    return new JsonToken(text.substring(index, current), current);
                }
            }
        }
        throw new IOException("invalid-json-body: unterminated structured value");
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
