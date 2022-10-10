package io.joern.ghidra2cpg

import io.joern.ghidra2cpg.Ghidra2Cpg
import io.shiftleft.x2cpg.{X2Cpg, X2CpgConfig}
import scopt.OParser

import java.io.File

/** Command line configuration parameters
  */
final case class Config(
                         input: Set[String] = Set.empty,
                         outputPath: String = X2CpgConfig.defaultOutputPath
) extends X2CpgConfig[Config] {

  override def withAdditionalInputPath(inputPath: String): Config =
    copy(input = input + inputPath)
  override def withOutputPath(x: String): Config = copy(outputPath = x)
}

object Main extends App {
  private val frontendSpecificOptions = {
    val builder = OParser.builder[Config]
    import builder.programName
    OParser.sequence(programName("ghidra2cpg"))
  }

  X2Cpg.parseCommandLine(args, frontendSpecificOptions, Config()) match {
    case Some(config) =>
      if (config.input.size == 1) {
        var input = config.input.head
        var inputArray = input.split("!")
        println(s"input : $input")
        if (inputArray.size != 3) {
          sys.exit(-1)
        }
        var projectPath = inputArray(0)
        var projectNameAndRoot = inputArray(1)
        var projectNameAndRootArray = projectNameAndRoot.split("/")
        var projectName: String = null
        var rootFolder: String = null
        if (projectNameAndRootArray.size == 1){
          projectName = projectNameAndRootArray(0)
          rootFolder = "/"
        } else {
          projectName = projectNameAndRootArray(0)
          rootFolder = projectNameAndRoot.substring(projectName.size)
        }

        var handleFile = inputArray(2)

        var inputFile = new File(config.input.head)
        var cpg = new Ghidra2Cpg(
          projectPath,
          projectName,
          rootFolder,
          handleFile,
          Some(config.outputPath)
        )
        cpg.String()

        cpg.createCpg()
        //cpg.close()
      } else {
        println("This frontend requires exactly one input path")
        System.exit(1)
      }
    case None =>
      System.exit(1)
  }

}
