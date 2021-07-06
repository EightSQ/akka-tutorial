package de.hpi.spark_tutorial

import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.functions.{col, collect_set}
import org.apache.spark.sql.types.DataType

object Sindy {

  def discoverINDs(inputs: List[String], spark: SparkSession): Unit = {
    import spark.implicits._

    val input_dss = inputs.map(csv_file =>
      spark
        .read
        .format("csv")
        .option("inferSchema", "true")
        .option("header", "true")
        .option("sep", ";")
        .load(csv_file)
        )

    val column_to_id = input_dss.flatMap(df => df.columns).zipWithIndex.toMap
    val id_to_column = input_dss.flatMap(df => df.columns).zipWithIndex.map(_.swap).toMap

    val flat_dss = input_dss.map(df =>
      df.flatMap(row =>
        row.schema.fieldNames.map(column =>
          (row.getAs(column).toString, column_to_id(column))
        )
      )
    )

    val tuples = flat_dss.reduce((accumulatorDF, nextDF) => accumulatorDF.union(nextDF))
    val attribute_sets = tuples.groupBy(tuples.columns(0)).agg(collect_set(tuples.columns(1))).drop("_1")

    val inclusion_lists = attribute_sets.flatMap(row =>
      row.getSeq[Integer](0).map { row_item =>
        (row_item, row.getSeq[Integer](0).filter(_ != row_item).toSet)
      }
    )

    val aggs = inclusion_lists.groupByKey(l => l._1).reduceGroups((a, b) => (a._1, a._2.intersect(b._2))).map {case (s, (_, l)) => (s, l) }.filter(row => row._2.nonEmpty).sort(col("_1").asc, col("_2").asc)

    aggs.collect().foreach { case (key, dependents) => println(id_to_column(key) + " < " + dependents.map(name => id_to_column(name)).mkString(", ")) }

}
}
