package io.joern.ghidra2cpg

import ghidra.GhidraJarApplicationLayout
import ghidra.app.decompiler.{DecompInterface, DecompileOptions}
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.{AutoImporter, MessageLog}
import ghidra.framework.model.{Project, ProjectLocator}
import ghidra.framework.project.{DefaultProject, DefaultProjectManager}
import ghidra.framework.protocol.ghidra.{GhidraURLConnection, Handler}
import ghidra.framework.{Application, HeadlessGhidraApplicationConfiguration}
import ghidra.program.database.ProgramContentHandler
import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.listing.Program
import ghidra.program.util.GhidraProgramUtilities
import ghidra.util.exception.InvalidInputException
import ghidra.util.task.TaskMonitor
import io.joern.ghidra2cpg.passes._
import io.joern.ghidra2cpg.processors._
import io.shiftleft.passes.KeyPoolCreator
import io.shiftleft.x2cpg.X2Cpg
import org.apache.commons.io.FileUtils
import utilities.util.FileUtilities

import java.io.{File, IOException}
import java.nio.file.Files
import scala.collection.mutable
import scala.jdk.CollectionConverters._
object Types {

  // Types will be added to the CPG as soon as everything
  // else is done
  val types: mutable.SortedSet[String] = scala.collection.mutable.SortedSet[String]()
  def registerType(typeName: String): String = {
    types += typeName
    typeName
  }
}
class Ghidra2Cpg(
                  projectPath: String,
                  projectName: String,
                  rootFolder: String,
                  handleFile: String,
                  outputFile: Option[String]

) {

  def String(): Unit = {
    println(s"project folder:\t$projectPath")
    println(s"project name:\t$projectName")
    println(s"input file: \t$handleFile")
    println(s"output file: \t$outputFile")
  }

  def createCpg(): Unit = {
    // We need this for the URL handler
    Handler.registerHandler()

    if (!Application.isInitialized) {
      var configuration = new HeadlessGhidraApplicationConfiguration
      configuration.setInitializeLogging(false)
      Application.initializeApplication(new GhidraJarApplicationLayout, configuration)
    }

    var project: Project = null
    var program: Program = null

    var projectManager: HeadlessGhidraProjectManager = new HeadlessGhidraProjectManager
    var dir = new File(projectPath)
    if (!dir.isDirectory) {
      println(s"$dir is not a directory")
    }

    var locator = new ProjectLocator(dir.getAbsolutePath, projectName)
    if (!locator.getProjectDir.exists) {
      println(s"$dir $projectName is not exist")
      sys.exit(-1)
    }
    try {
      project = new HeadlessProject(projectManager, locator)
      var domFolder = project.getProjectData.getFolder(rootFolder)
      if (domFolder == null) {
        println(s"$rootFolder$handleFile is not found")
        sys.exit(-1)
      }
      if (domFolder.isEmpty) {
        println(s"$rootFolder$handleFile is empty")
        sys.exit(-1)
      }

      var domFile = domFolder.getFile(handleFile)
      if (domFile == null) {
        println(s"$rootFolder$handleFile is not found")
        sys.exit(-1)
      }

      if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(domFile.getContentType)) {
        println(s"$rootFolder$handleFile is not program type")
        sys.exit(-1)
      }

      var domObject =  domFile.getDomainObject(this,true, false, TaskMonitor.DUMMY)
      program = domObject.asInstanceOf[Program]
      analyzeProgram(domFile.getPathname, program)
    } catch {
      case e: Throwable =>
        e.printStackTrace()
    } finally {
      if (program != null) {
        AutoAnalysisManager.getAnalysisManager(program).dispose()
        program.release(this)
        program = null
      }
      project.close()
      // Used to have this in a config but we delete the directory anyway
      // if (!config.runScriptsNoImport && config.deleteProject)
    }
  }
  private def analyzeProgram(fileAbsolutePath: String, program: Program): Unit = {
    val autoAnalysisManager: AutoAnalysisManager = AutoAnalysisManager.getAnalysisManager(program)
    val transactionId: Int                       = program.startTransaction("Analysis")
    try {
      autoAnalysisManager.initializeOptions()
      autoAnalysisManager.reAnalyzeAll(null)
      autoAnalysisManager.startAnalysis(TaskMonitor.DUMMY)
      GhidraProgramUtilities.setAnalyzedFlag(program, true)
    } catch {
      case e: Throwable =>
        e.printStackTrace()
    } finally {
      program.endTransaction(transactionId, true)
    }
    try {
      handleProgram(program, fileAbsolutePath)
    } catch {
      case e: Throwable =>
        e.printStackTrace()
    }
  }

  def handleProgram(currentProgram: Program, fileAbsolutePath: String): Unit = {

    val flatProgramAPI: FlatProgramAPI = new FlatProgramAPI(currentProgram)
    val decompilerInterface            = new DecompInterface()
    decompilerInterface.toggleCCode(false)
    decompilerInterface.toggleSyntaxTree(false)
    decompilerInterface.toggleJumpLoads(false)
    decompilerInterface.toggleParamMeasures(true)
    decompilerInterface.setSimplificationStyle("decompile")

    val opts = new DecompileOptions()

    opts.grabFromProgram(currentProgram)
    decompilerInterface.setOptions(opts)

    println(s"""[ + ] Starting CPG generation""")
    if (!decompilerInterface.openProgram(currentProgram)) {
      println("Decompiler error: %s\n", decompilerInterface.getLastMessage)
    }
    // Functions
    val listing          = currentProgram.getListing
    val functionIterator = listing.getFunctions(true)
    val functions        = functionIterator.iterator.asScala.toList

    // We touch every function twice, regular ASM and PCode
    // Also we have + 2 for MetaDataPass and Namespacepass
    val numOfKeypools   = functions.size * 3 + 2
    val keyPoolIterator = KeyPoolCreator.obtain(numOfKeypools).iterator

    // Actual CPG construction
    val cpg = X2Cpg.newEmptyCpg(outputFile)

    new MetaDataPass(fileAbsolutePath, cpg, keyPoolIterator.next()).createAndApply()
    new NamespacePass(cpg, fileAbsolutePath, keyPoolIterator.next()).createAndApply()

    val processor = currentProgram.getLanguage.getLanguageDescription.getProcessor.toString match {
      case "MIPS"    => new Mips
      case "AARCH64" => new Arm
      case _         => new X86
    }

    functions.foreach { function =>
      new FunctionPass(
        processor,
        currentProgram,
        fileAbsolutePath,
        functions,
        function,
        cpg,
        keyPoolIterator.next,
        decompilerInterface
      )
        .createAndApply()
    }

    new TypesPass(cpg).createAndApply()
    new JumpPass(cpg, keyPoolIterator.next).createAndApply()
    new LiteralPass(cpg, currentProgram, flatProgramAPI, keyPoolIterator.next).createAndApply()
    cpg.close()
  }

  private class HeadlessProjectConnection(
      projectManager: HeadlessGhidraProjectManager,
      connection: GhidraURLConnection
  ) extends DefaultProject(projectManager, connection) {}

  private class HeadlessGhidraProjectManager extends DefaultProjectManager {}
  private class HeadlessProject(projectManager : HeadlessGhidraProjectManager , locator: ProjectLocator ) extends DefaultProject(projectManager, locator, false) {}
}
