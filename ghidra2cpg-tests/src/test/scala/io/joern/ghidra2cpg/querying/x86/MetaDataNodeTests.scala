package io.joern.ghidra2cpg.querying.x86

import io.joern.ghidra2cpg.fixtures.GhidraBinToCpgSuite
import io.shiftleft.semanticcpg.language._

class MetaDataNodeTests extends GhidraBinToCpgSuite {

  override def beforeAll(): Unit = {
    super.beforeAll()
    buildCpgForBin("x86_64.bin")
  }

  "should contain exactly one node with all mandatory fields set" in {
    cpg.metaData.l match {
      case List(x) =>
        x.language shouldBe "Ghidra"
        x.version shouldBe "0.1"
        x.overlays shouldBe List("semanticcpg")
      case _ => fail()
    }
  }
}